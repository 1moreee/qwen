# =============================================================================
# Файл: app.py
# Тема курсової роботи: Формування автоматизованого звіту про мережеву
#                        активність за заданий період
# Дисципліна: Алгоритмізація та програмування
# Спеціальність: 125 «Кібербезпека та захист інформації»
# Стек: Python · Streamlit · Pandas · Plotly
# =============================================================================

# ---------- Стандартні бібліотеки ----------
import io                   # Робота з байтовими потоками (для CSV-буфера)
import csv                  # Генерація тестового CSV-файлу
import random               # Генерація псевдовипадкових даних для демо-файлу
from datetime import datetime, timedelta  # Маніпуляції з датою і часом
import urllib.request       # Завантаження CSV-файлу за URL з репозиторію

# ---------- Сторонні бібліотеки ----------
import pandas as pd         # Основна бібліотека для табличного аналізу даних
import plotly.express as px # Інтерактивні графіки на базі Plotly Express
import plotly.graph_objects as go  # Низькорівневий API Plotly для складних фігур
import streamlit as st      # Фреймворк для побудови веб-дашбордів


# =============================================================================
# КЛАС NetworkAnalyzer — головний модуль бізнес-логіки
# Відповідає за завантаження, валідацію, обробку та аналіз мережевих логів.
# Вся логіка інкапсульована всередині класу, що відповідає принципам ООП:
# єдина відповідальність (SRP) та інкапсуляція стану об'єкта.
# =============================================================================
class NetworkAnalyzer:
    """
    Клас для аналізу мережевого трафіку на основі CSV-журналів.

    Атрибути
    --------
    REQUIRED_COLUMNS : set
        Множина обов'язкових назв колонок. Використання set забезпечує
        перевірку наявності колонок за O(1).
    PACKET_THRESHOLD : int
        Порогова кількість пакетів з однієї IP-адреси, що вважається
        підозрілою активністю.
    BYTES_THRESHOLD : int
        Пороговий обсяг трафіку (у байтах) з однієї IP-адреси.
    """

    # --- Константи класу (порогові значення для виявлення аномалій) ---
    REQUIRED_COLUMNS: set = {"Source IP", "Destination IP", "Protocol",
                             "Port", "Size", "Time"}
    PACKET_THRESHOLD: int = 1_000   # Понад 1000 пакетів — підозріла активність
    BYTES_THRESHOLD:  int = 50_000_000  # Понад 50 МБ з однієї IP — аномалія

    # ------------------------------------------------------------------
    def __init__(self, dataframe: pd.DataFrame) -> None:
        """
        Ініціалізація аналізатора.

        Параметри
        ----------
        dataframe : pd.DataFrame
            «Сирий» DataFrame, прочитаний із CSV-файлу.
            Зберігається як незмінна копія; всі операції над df є похідними.
        """
        # Зберігаємо оригінальний DataFrame як атрибут об'єкта
        self.df: pd.DataFrame = dataframe.copy()

        # Конвертуємо колонку Time у тип datetime для коректних часових операцій
        # errors='coerce' замінює непарсовані значення на NaT замість виключення
        self.df["Time"] = pd.to_datetime(self.df["Time"], errors="coerce")

        # Видаляємо рядки, де час не вдалося розпізнати (NaT)
        self.df.dropna(subset=["Time"], inplace=True)

        # Конвертуємо Size у числовий тип; некоректні значення → NaN → 0
        self.df["Size"] = pd.to_numeric(self.df["Size"], errors="coerce").fillna(0)

    # ------------------------------------------------------------------
    @staticmethod
    def validate(dataframe: pd.DataFrame) -> tuple[bool, str]:
        """
        Статичний метод валідації DataFrame до створення екземпляра класу.
        Не потребує self, бо не звертається до стану об'єкта.

        Повертає
        --------
        tuple[bool, str]
            (True, "") — якщо DataFrame валідний;
            (False, повідомлення_про_помилку) — у разі проблем.
        """
        # Перевірка 1: DataFrame не порожній
        if dataframe.empty:
            return False, "CSV-файл порожній або не містить рядків даних."

        # Перевірка 2: наявність усіх обов'язкових колонок.
        # Використовуємо операцію різниці множин — ефективна та читабельна.
        missing: set = NetworkAnalyzer.REQUIRED_COLUMNS - set(dataframe.columns)
        if missing:
            return False, f"Відсутні обов'язкові колонки: {', '.join(sorted(missing))}"

        return True, ""

    # ------------------------------------------------------------------
    def filter_by_period(self, start: datetime, end: datetime) -> "NetworkAnalyzer":
        """
        Повертає новий екземпляр NetworkAnalyzer, що містить лише записи
        у заданому часовому діапазоні [start, end].

        Параметри
        ----------
        start : datetime  — початок діапазону (включно)
        end   : datetime  — кінець діапазону (включно)

        Повертає
        --------
        NetworkAnalyzer — новий об'єкт із відфільтрованим DataFrame.
        """
        # Булева маска для рядків, де час потрапляє у вказаний діапазон
        mask = (self.df["Time"] >= pd.Timestamp(start)) & \
               (self.df["Time"] <= pd.Timestamp(end))
        return NetworkAnalyzer(self.df.loc[mask].reset_index(drop=True))

    # ------------------------------------------------------------------
    def filter_by_protocol(self, protocols: list[str]) -> "NetworkAnalyzer":
        """
        Фільтрує DataFrame за списком обраних протоколів.
        Демонстрація функціонального програмування: використовується
        lambda-вираз у поєднанні з isin() — еквівалент filter(lambda x: ...).

        Параметри
        ----------
        protocols : list[str]
            Список протоколів, наприклад ["TCP", "UDP"].
        """
        if not protocols:
            return self  # Якщо список порожній — повертаємо без змін

        # Функціональний стиль: lambda перевіряє приналежність значення списку.
        # map() застосовує lambda до кожного рядка колонки Protocol.
        mask = list(map(lambda p: p in protocols, self.df["Protocol"]))
        return NetworkAnalyzer(self.df[mask].reset_index(drop=True))

    # ------------------------------------------------------------------
    def filter_by_port(self, port: int | None) -> "NetworkAnalyzer":
        """
        Фільтрує записи за конкретним номером порту.
        Якщо port=None — фільтрація не застосовується.

        Демонстрація filter() із lambda — функціональне програмування:
        filter(lambda row: row["Port"] == port, records)
        """
        if port is None:
            return self

        # Конвертуємо DataFrame у список словників для демонстрації filter()
        records: list[dict] = self.df.to_dict("records")

        # filter() повертає ітератор рядків, де Port збігається із заданим
        filtered_records = list(filter(lambda row: row["Port"] == port, records))

        if not filtered_records:
            # Якщо жоден рядок не пройшов фільтр — повертаємо порожній DF
            return NetworkAnalyzer(pd.DataFrame(columns=self.df.columns))

        return NetworkAnalyzer(pd.DataFrame(filtered_records))

    # ------------------------------------------------------------------
    def total_traffic(self) -> dict:
        """
        Підраховує загальний обсяг трафіку та базові метрики.

        Повертає
        --------
        dict із ключами:
            total_bytes   — сума всіх розмірів пакетів у байтах
            total_mb      — те саме, у мегабайтах (округлено до 2 знаків)
            total_packets — кількість рядків (пакетів) у DataFrame
            unique_ips    — кількість унікальних IP-адрес (src + dst у множині)
        """
        # Сума байтів через pandas — векторизована операція (швидко)
        total_bytes: int = int(self.df["Size"].sum())

        # Множина унікальних IP-адрес — об'єднання source і destination.
        # set() гарантує відсутність дублікатів без додаткових умов.
        unique_src: set = set(self.df["Source IP"].dropna().unique())
        unique_dst: set = set(self.df["Destination IP"].dropna().unique())
        unique_ips: set = unique_src | unique_dst  # Оператор об'єднання множин

        return {
            "total_bytes":   total_bytes,
            "total_mb":      round(total_bytes / 1_048_576, 2),  # 1 МБ = 2^20 байт
            "total_packets": len(self.df),
            "unique_ips":    len(unique_ips),
        }

    # ------------------------------------------------------------------
    def top_sources(self, n: int = 5) -> pd.DataFrame:
        """
        Визначає топ-N IP-адрес відправників за кількістю пакетів та обсягом.

        Параметри
        ----------
        n : int — кількість позицій у топ-списку (за замовчуванням 5)
        """
        return (
            self.df.groupby("Source IP")
            .agg(
                Пакетів=("Size", "count"),       # Кількість рядків (пакетів)
                Байтів=("Size", "sum"),           # Сума байтів
            )
            .sort_values("Пакетів", ascending=False)
            .head(n)
            .reset_index()
            .rename(columns={"Source IP": "IP-адреса відправника"})
        )

    # ------------------------------------------------------------------
    def top_destinations(self, n: int = 5) -> pd.DataFrame:
        """
        Визначає топ-N IP-адрес отримувачів за кількістю пакетів.
        """
        return (
            self.df.groupby("Destination IP")
            .agg(
                Пакетів=("Size", "count"),
                Байтів=("Size", "sum"),
            )
            .sort_values("Пакетів", ascending=False)
            .head(n)
            .reset_index()
            .rename(columns={"Destination IP": "IP-адреса отримувача"})
        )

    # ------------------------------------------------------------------
    def protocol_distribution(self) -> pd.DataFrame:
        """
        Підраховує розподіл пакетів і трафіку за протоколами (TCP/UDP/ICMP…).
        """
        return (
            self.df.groupby("Protocol")
            .agg(
                Пакетів=("Size", "count"),
                Байтів=("Size", "sum"),
            )
            .sort_values("Пакетів", ascending=False)
            .reset_index()
            .rename(columns={"Protocol": "Протокол"})
        )

    # ------------------------------------------------------------------
    def traffic_over_time(self, freq: str = "1min") -> pd.DataFrame:
        """
        Агрегує трафік за часовим інтервалом для побудови часового графіка.

        Параметри
        ----------
        freq : str — частота ресемплювання у форматі pandas offset alias.
                     Наприклад: "1min", "5min", "1h", "1D".
        """
        # Встановлюємо Time як індекс для ресемплювання
        ts = self.df.set_index("Time")

        # resample() дробить ряд на рівні інтервали та агрегує
        return (
            ts["Size"]
            .resample(freq)
            .agg(["sum", "count"])
            .rename(columns={"sum": "Байтів", "count": "Пакетів"})
            .reset_index()
            .rename(columns={"Time": "Час"})
        )

    # ------------------------------------------------------------------
    def port_distribution(self, top_n: int = 10) -> pd.DataFrame:
        """
        Розподіл трафіку за номерами портів (топ-N найактивніших).
        """
        return (
            self.df.groupby("Port")
            .agg(Пакетів=("Size", "count"), Байтів=("Size", "sum"))
            .sort_values("Пакетів", ascending=False)
            .head(top_n)
            .reset_index()
            .rename(columns={"Port": "Порт"})
        )

    # ------------------------------------------------------------------
    def detect_anomalies(self) -> dict:
        """
        Виявлення підозрілої мережевої активності за двома критеріями:

        1. IP-адреси, що надіслали понад PACKET_THRESHOLD пакетів —
           можлива DDoS-атака або сканування портів.
        2. IP-адреси з обсягом трафіку понад BYTES_THRESHOLD байтів —
           можливий витік або ексфільтрація даних.

        Повертає
        --------
        dict із двома ключами: "high_packet" та "high_volume" —
        кожен містить список словників з деталями аномалії.
        """
        # Групуємо за Source IP, підраховуємо пакети та байти
        grouped = (
            self.df.groupby("Source IP")
            .agg(packets=("Size", "count"), bytes_=("Size", "sum"))
            .reset_index()
        )

        # Словник для збереження результатів аналізу аномалій
        anomalies: dict = {"high_packet": [], "high_volume": []}

        # Ітерація по рядках згрупованого DataFrame
        for _, row in grouped.iterrows():
            # Критерій 1: висока кількість пакетів
            if row["packets"] > self.PACKET_THRESHOLD:
                anomalies["high_packet"].append({
                    "IP": row["Source IP"],
                    "Пакетів": int(row["packets"]),
                    "Байтів": int(row["bytes_"]),
                })
            # Критерій 2: великий обсяг переданих даних
            if row["bytes_"] > self.BYTES_THRESHOLD:
                anomalies["high_volume"].append({
                    "IP": row["Source IP"],
                    "Пакетів": int(row["packets"]),
                    "Байтів": int(row["bytes_"]),
                    "МБ": round(row["bytes_"] / 1_048_576, 2),
                })

        return anomalies


# =============================================================================
# ФУНКЦІЯ generate_demo_csv — генератор тестових даних
# Створює синтетичний CSV-файл для демонстрації роботи дашборду
# без реального мережевого обладнання.
# =============================================================================
def generate_demo_csv() -> bytes:
    """
    Генерує демонстраційний CSV-файл із псевдовипадковими мережевими логами.

    Структура файлу відповідає специфікації:
        Source IP, Destination IP, Protocol, Port, Size, Time

    Повертає
    --------
    bytes — вміст CSV-файлу як байтовий рядок, готовий до завантаження.
    """
    # Пул IP-адрес: більшість «нормальні», кілька — «аномальні» (багато пакетів)
    normal_ips: list[str] = [
        f"192.168.1.{i}" for i in range(1, 20)
    ]
    # Атакуючі IP — надсилатимуть понад 1000 пакетів
    attacker_ips: list[str] = ["10.0.0.99", "172.16.0.5"]

    # Пул протоколів та відповідних портів (словник для семантичного зв'язку)
    protocol_ports: dict[str, list[int]] = {
        "TCP":  [80, 443, 22, 3389, 8080],
        "UDP":  [53, 123, 161, 5353],
        "ICMP": [0],  # ICMP не має портів; 0 — умовне позначення
    }

    # Базова мітка часу — 24 години тому від поточного моменту
    base_time: datetime = datetime.now() - timedelta(hours=24)

    # Буфер у пам'яті замість файлу на диску
    output = io.StringIO()
    writer = csv.writer(output)

    # Запис заголовка
    writer.writerow(["Source IP", "Destination IP", "Protocol", "Port",
                     "Size", "Time"])

    # --- Генерація нормальних записів (2000 рядків) ---
    for i in range(2000):
        src = random.choice(normal_ips)
        dst = random.choice(normal_ips + ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
        proto = random.choice(list(protocol_ports.keys()))
        port = random.choice(protocol_ports[proto])
        size = random.randint(64, 65_535)   # Розмір пакету: 64 Б — 64 КБ
        # Час рівномірно розподілений у межах 24 годин
        ts = base_time + timedelta(seconds=random.randint(0, 86_400))
        writer.writerow([src, dst, proto, port, size,
                         ts.strftime("%Y-%m-%d %H:%M:%S")])

    # --- Генерація аномальних записів (1200 рядків від «атакуючих» IP) ---
    for i in range(1200):
        src = random.choice(attacker_ips)
        dst = random.choice(normal_ips)
        proto = "TCP"
        port = random.choice([80, 443, 22])
        # Аномально великі пакети — ознака ексфільтрації даних
        size = random.randint(500_000, 2_000_000)
        ts = base_time + timedelta(seconds=random.randint(0, 86_400))
        writer.writerow([src, dst, proto, port, size,
                         ts.strftime("%Y-%m-%d %H:%M:%S")])

    # Повертаємо вміст буфера у вигляді байтів (UTF-8)
    return output.getvalue().encode("utf-8")


# =============================================================================
# ФУНКЦІЯ build_dashboard — головна функція побудови інтерфейсу Streamlit
# Описує весь UI дашборду: бічна панель, метрики, графіки, таблиці, аномалії.
# =============================================================================
def build_dashboard() -> None:
    """
    Формує інтерфейс веб-дашборду за допомогою Streamlit.
    Виклик цієї функції є точкою входу програми.
    """

    # ---- Загальні налаштування сторінки ----
    st.set_page_config(
        page_title="Аналіз мережевої активності",
        page_icon="🛡️",
        layout="wide",                   # Широке розташування для дашборду
        initial_sidebar_state="expanded",
    )

    # ---- Кастомні CSS-стилі для покращення вигляду ----
    st.markdown("""
    <style>
        /* Загальний фон і шрифт */
        .stApp { background-color: #0d1117; color: #e6edf3; }
        /* Картки метрик */
        [data-testid="stMetric"] {
            background: linear-gradient(135deg, #161b22 0%, #1c2433 100%);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 16px;
        }
        [data-testid="stMetricValue"] { color: #58a6ff; font-size: 2rem; font-weight: 700; }
        [data-testid="stMetricLabel"] { color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }
        /* Заголовок */
        .dash-header {
            background: linear-gradient(90deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
            border-bottom: 1px solid #21262d;
            padding: 20px 0 16px 0;
            margin-bottom: 24px;
        }
        .dash-title {
            font-size: 2rem; font-weight: 800; letter-spacing: -0.5px;
            background: linear-gradient(90deg, #58a6ff, #79c0ff, #a5d6ff);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .dash-sub { color: #8b949e; font-size: 0.9rem; margin-top: 4px; }
        /* Секції */
        .section-header {
            color: #c9d1d9; font-size: 1.1rem; font-weight: 600;
            border-left: 3px solid #58a6ff; padding-left: 10px;
            margin: 24px 0 12px 0;
        }
        /* Бічна панель */
        [data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #30363d; }
        /* Таблиці */
        .stDataFrame { border: 1px solid #30363d; border-radius: 8px; }
    </style>
    """, unsafe_allow_html=True)

    # ---- Заголовок дашборду ----
    st.markdown("""
    <div class="dash-header">
        <div class="dash-title">🛡️ Аналіз мережевої активності</div>
        <div class="dash-sub">
            Автоматизований звіт · Кібербезпека та захист інформації
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ==========================================================================
    # БІЧНА ПАНЕЛЬ — завантаження файлу та фільтри
    # ==========================================================================
    # URL до raw CSV-файлу у GitHub-репозиторії
    # Замініть це посилання на актуальне посилання вашого репозиторію
    CSV_URL: str = (
        "https://raw.githubusercontent.com/1moreee/qwen/refs/heads/main/sample_network_logs.csv"
        "main/sample_network_logs.csv"
    )

    with st.sidebar:
        st.markdown("### 📂 Джерело даних")

        # Поле для введення/зміни URL репозиторію
        csv_url = st.text_input(
            "URL до CSV-файлу (raw)",
            value=CSV_URL,
            help="Посилання на raw CSV-файл у GitHub-репозиторії",
        )

        st.markdown("---")

        # Кнопка для ручного перезавантаження файлу
        reload = st.button("🔄 Оновити дані з репозиторію")

    # ==========================================================================
    # ЗАВАНТАЖЕННЯ CSV З РЕПОЗИТОРІЮ
    # Використовуємо st.session_state для кешування даних між перезапусками.
    # ==========================================================================

    # Завантажуємо дані якщо ще не завантажено, або натиснуто "Оновити"
    if "repo_df" not in st.session_state or reload:
        with st.spinner("Завантаження CSV-файлу з репозиторію..."):
            try:
                with urllib.request.urlopen(csv_url, timeout=10) as response:
                    csv_bytes = response.read()
                st.session_state["repo_df"] = csv_bytes
                st.session_state["repo_url"] = csv_url
                if reload:
                    st.success("Дані успішно оновлено з репозиторію.")
            except urllib.error.HTTPError as e:
                st.error(
                    f"HTTP-помилка {e.code}: не вдалося завантажити файл.\n"
                    "Перевірте правильність URL та доступність репозиторію."
                )
                return
            except urllib.error.URLError as e:
                st.error(
                    f"Помилка мережі: {e.reason}\n"
                    "Перевірте підключення до Інтернету та URL-адресу."
                )
                return
            except Exception as e:
                st.error(f"Непередбачена помилка завантаження: {e}")
                return

    # Отримуємо збережений CSV з session_state
    csv_source = io.BytesIO(st.session_state["repo_df"])

    # Показуємо інформацію про джерело даних
    st.caption(f"Джерело: `{st.session_state.get('repo_url', csv_url)}`")

    # ==========================================================================
    # ЧИТАННЯ ТА ВАЛІДАЦІЯ ФАЙЛУ
    # Блок try-except перехоплює типові помилки при роботі з CSV.
    # ==========================================================================
    try:
        # Зчитуємо CSV у DataFrame; sep=',' — стандартний роздільник
        raw_df = pd.read_csv(csv_source, sep=",")

    except pd.errors.EmptyDataError:
        # Виняток: файл існує, але порожній або містить лише заголовок
        st.error("❌ Файл порожній або пошкоджений. Перевірте вміст CSV.")
        return

    except pd.errors.ParserError as e:
        # Виняток: файл не вдалося розібрати як CSV (неправильний формат)
        st.error(f"❌ Помилка розбору CSV-файлу: {e}")
        return

    except Exception as e:
        # Загальний виняток для непередбачених помилок читання
        st.error(f"❌ Непередбачена помилка: {e}")
        return

    # Валідація структури DataFrame (наявність обов'язкових колонок)
    is_valid, error_msg = NetworkAnalyzer.validate(raw_df)
    if not is_valid:
        st.error(f"❌ Файл не відповідає вимогам: {error_msg}")
        return

    # Ціль валідації досягнута — створюємо екземпляр аналізатора
    analyzer = NetworkAnalyzer(raw_df)

    # ==========================================================================
    # ПРОДОВЖЕННЯ БІЧНОЇ ПАНЕЛІ — фільтри (після перевірки файлу)
    # ==========================================================================
    with st.sidebar:
        st.markdown("### 🔍 Фільтри аналізу")

        # --- Фільтр за часовим діапазоном ---
        min_time = analyzer.df["Time"].min().to_pydatetime()
        max_time = analyzer.df["Time"].max().to_pydatetime()

        st.markdown("**Часовий діапазон**")
        start_dt = st.date_input("Від", value=min_time.date(),
                                 min_value=min_time.date(),
                                 max_value=max_time.date())
        end_dt   = st.date_input("До", value=max_time.date(),
                                 min_value=min_time.date(),
                                 max_value=max_time.date())

        # Конвертуємо date → datetime для порівняння з Timestamp
        start_datetime = datetime.combine(start_dt, datetime.min.time())
        end_datetime   = datetime.combine(end_dt,   datetime.max.time())

        # --- Фільтр за протоколами ---
        st.markdown("**Протоколи**")
        available_protocols: list[str] = sorted(
            analyzer.df["Protocol"].dropna().unique().tolist()
        )
        selected_protocols = st.multiselect(
            "Оберіть протоколи",
            options=available_protocols,
            default=available_protocols,
        )

        # --- Фільтр за портом ---
        st.markdown("**Фільтр за портом**")
        port_filter = st.number_input(
            "Порт (0 = без фільтру)",
            min_value=0, max_value=65535, value=0, step=1,
        )
        port_value: int | None = int(port_filter) if port_filter > 0 else None

        # --- Гранулярність часового графіка ---
        st.markdown("**Гранулярність графіка**")
        freq_map: dict[str, str] = {
            "1 хвилина": "1min",
            "5 хвилин":  "5min",
            "15 хвилин": "15min",
            "1 година":  "1h",
            "1 день":    "1D",
        }
        freq_label = st.selectbox("Інтервал агрегації",
                                  options=list(freq_map.keys()), index=2)
        freq = freq_map[freq_label]

        st.markdown("---")
        st.caption("🔒 Дані обробляються локально. Файл не передається в мережу.")

    # ==========================================================================
    # ЗАСТОСУВАННЯ ФІЛЬТРІВ
    # Ланцюжок методів — кожен повертає новий NetworkAnalyzer (незмінність стану)
    # ==========================================================================
    try:
        filtered = (
            analyzer
            .filter_by_period(start_datetime, end_datetime)
            .filter_by_protocol(selected_protocols)
            .filter_by_port(port_value)
        )
    except KeyError as e:
        # Виняток: спроба звернутися до неіснуючої колонки під час фільтрації
        st.error(f"❌ Помилка фільтрації (відсутня колонка): {e}")
        return

    # Перевірка: після фільтрації може не залишитися жодного запису
    if filtered.df.empty:
        st.warning("⚠️ За обраними фільтрами не знайдено жодного запису. "
                   "Спробуйте розширити діапазон або змінити фільтри.")
        return

    # ==========================================================================
    # БЛОК МЕТРИК — верхній рядок зведених показників
    # ==========================================================================
    stats = filtered.total_traffic()

    st.markdown('<div class="section-header">📊 Зведені показники</div>',
                unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Загальний трафік",
            value=f"{stats['total_mb']:,.2f} МБ",
            help="Сума розмірів усіх пакетів у вибірці",
        )
    with col2:
        st.metric(
            label="Кількість пакетів",
            value=f"{stats['total_packets']:,}",
            help="Загальна кількість рядків (записів) у журналі",
        )
    with col3:
        st.metric(
            label="Унікальних IP-адрес",
            value=f"{stats['unique_ips']:,}",
            help="Кількість унікальних IP у Source IP ∪ Destination IP",
        )
    with col4:
        # Розрахунок середнього розміру пакету для додаткового контексту
        avg_size = stats['total_bytes'] / stats['total_packets'] \
            if stats['total_packets'] > 0 else 0
        st.metric(
            label="Середній розмір пакету",
            value=f"{avg_size:,.0f} Б",
            help="Середній розмір одного пакету у байтах",
        )

    # ==========================================================================
    # ГРАФІК ТРАФІКУ В ЧАСІ
    # ==========================================================================
    st.markdown('<div class="section-header">📈 Динаміка трафіку</div>',
                unsafe_allow_html=True)

    try:
        time_df = filtered.traffic_over_time(freq=freq)

        # Plotly Express — інтерактивний лінійний графік
        fig_time = px.line(
            time_df,
            x="Час",
            y="Байтів",
            title=f"Обсяг трафіку (агрегація: {freq_label})",
            labels={"Байтів": "Байтів", "Час": ""},
            color_discrete_sequence=["#58a6ff"],
        )
        # Налаштування кольорової схеми для темного фону
        fig_time.update_layout(
            plot_bgcolor="#161b22",
            paper_bgcolor="#0d1117",
            font_color="#c9d1d9",
            title_font_color="#e6edf3",
            xaxis=dict(gridcolor="#21262d", linecolor="#30363d"),
            yaxis=dict(gridcolor="#21262d", linecolor="#30363d"),
            hovermode="x unified",
        )
        fig_time.update_traces(fill="tozeroy", fillcolor="rgba(88,166,255,0.1)")
        st.plotly_chart(fig_time, use_container_width=True)

    except Exception as e:
        st.warning(f"⚠️ Не вдалося побудувати часовий графік: {e}")

    # ==========================================================================
    # ДВА СТОВПЦІ: Протоколи та Порти
    # ==========================================================================
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown('<div class="section-header">🔵 Розподіл за протоколами</div>',
                    unsafe_allow_html=True)
        try:
            proto_df = filtered.protocol_distribution()

            fig_proto = px.pie(
                proto_df,
                names="Протокол",
                values="Пакетів",
                hole=0.4,   # Donut-chart — сучасніший вигляд
                color_discrete_sequence=["#58a6ff", "#3fb950", "#f78166",
                                         "#d2a8ff", "#ffa657"],
            )
            fig_proto.update_layout(
                plot_bgcolor="#161b22",
                paper_bgcolor="#161b22",
                font_color="#c9d1d9",
                showlegend=True,
                legend=dict(bgcolor="#161b22"),
            )
            st.plotly_chart(fig_proto, use_container_width=True)

            # Таблиця під графіком
            st.dataframe(proto_df, use_container_width=True, hide_index=True)

        except Exception as e:
            st.warning(f"⚠️ Помилка розподілу за протоколами: {e}")

    with col_right:
        st.markdown('<div class="section-header">🔌 Топ-10 портів</div>',
                    unsafe_allow_html=True)
        try:
            port_df = filtered.port_distribution(top_n=10)

            fig_port = px.bar(
                port_df,
                x="Порт",
                y="Пакетів",
                color="Пакетів",
                color_continuous_scale=["#0d1117", "#58a6ff"],
                text="Пакетів",
            )
            fig_port.update_layout(
                plot_bgcolor="#161b22",
                paper_bgcolor="#161b22",
                font_color="#c9d1d9",
                xaxis=dict(type="category", gridcolor="#21262d"),
                yaxis=dict(gridcolor="#21262d"),
                coloraxis_showscale=False,
            )
            fig_port.update_traces(textposition="outside",
                                   textfont_color="#c9d1d9")
            st.plotly_chart(fig_port, use_container_width=True)

        except Exception as e:
            st.warning(f"⚠️ Помилка розподілу за портами: {e}")

    # ==========================================================================
    # ТОП IP-АДРЕС
    # ==========================================================================
    st.markdown('<div class="section-header">🏆 Топ IP-адрес</div>',
                unsafe_allow_html=True)

    col_src, col_dst = st.columns(2)

    with col_src:
        st.markdown("**Відправники (Source IP)**")
        try:
            src_df = filtered.top_sources(n=5)
            st.dataframe(src_df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.warning(f"⚠️ {e}")

    with col_dst:
        st.markdown("**Отримувачі (Destination IP)**")
        try:
            dst_df = filtered.top_destinations(n=5)
            st.dataframe(dst_df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.warning(f"⚠️ {e}")

    # ==========================================================================
    # ВИЯВЛЕННЯ АНОМАЛІЙ
    # ==========================================================================
    st.markdown('<div class="section-header">🚨 Виявлені аномалії</div>',
                unsafe_allow_html=True)

    try:
        anomalies = filtered.detect_anomalies()

        # --- Аномалія 1: висока кількість пакетів ---
        if anomalies["high_packet"]:
            st.error(
                f"🔴 Виявлено {len(anomalies['high_packet'])} IP-адрес(у) "
                f"з понад {NetworkAnalyzer.PACKET_THRESHOLD:,} пакетів — "
                "можлива DDoS-атака або сканування портів!"
            )
            anom_pkt_df = pd.DataFrame(anomalies["high_packet"])
            # Стилізація: виділяємо рядки з найбільшою кількістю пакетів
            st.dataframe(
                anom_pkt_df.style.highlight_max(
                    subset=["Пакетів"], color="#3d1a1a"
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("✅ Аномальної кількості пакетів не виявлено.")

        # --- Аномалія 2: великий обсяг трафіку ---
        if anomalies["high_volume"]:
            threshold_mb = NetworkAnalyzer.BYTES_THRESHOLD / 1_048_576
            st.error(
                f"🔴 Виявлено {len(anomalies['high_volume'])} IP-адрес(у) "
                f"з обсягом трафіку понад {threshold_mb:.0f} МБ — "
                "можлива ексфільтрація даних!"
            )
            anom_vol_df = pd.DataFrame(anomalies["high_volume"])
            st.dataframe(
                anom_vol_df.style.highlight_max(
                    subset=["МБ"], color="#3d1a1a"
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("✅ Аномального обсягу трафіку не виявлено.")

    except Exception as e:
        st.warning(f"⚠️ Помилка під час аналізу аномалій: {e}")

    # ==========================================================================
    # СИРІ ДАНІ — повна таблиця для ручної перевірки
    # ==========================================================================
    with st.expander("📋 Переглянути сирі дані (перші 500 рядків)", expanded=False):
        st.dataframe(
            filtered.df.head(500),
            use_container_width=True,
            hide_index=True,
        )

    # ==========================================================================
    # ПІДВАЛ СТОРІНКИ
    # ==========================================================================
    st.markdown("---")
    st.caption(
        "🛡️ Автоматизований звіт про мережеву активність · "
        "Дисципліна: Алгоритмізація та програмування · "
        "Спеціальність 125 «Кібербезпека та захист інформації»"
    )


# =============================================================================
# ТОЧКА ВХОДУ
# Виклик build_dashboard() запускає весь веб-додаток.
# Streamlit сам виконує цей файл зверху вниз при кожному оновленні інтерфейсу.
# =============================================================================
if __name__ == "__main__":
    build_dashboard()
