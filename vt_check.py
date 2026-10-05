import os                    # ← модуль для работы с системой (нужен, чтобы достать ключ)
import requests              # ← библиотека для запросов в интернет

api_key = os.environ["VT_API_KEY"]                     # ← ключ берём из переменной окружения, не из кода
target = input("Введите IP или домен: ").strip()       # ← спрашиваем, что проверить; strip() убирает пробелы по краям

if target.replace(".", "").isdigit():                  # ← убрали точки: остались одни цифры? значит, это IP
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
else:                                                  # ← иначе считаем, что это домен
    url = f"https://www.virustotal.com/api/v3/domains/{target}"

response = requests.get(url, headers={"x-apikey": api_key})   # ← отправляем «письмо» с пропуском

if response.status_code == 200:                        # ← 200 = ответ пришёл, всё хорошо
    data = response.json()                             # ← превращаем ответ в словарь
    stats = data["data"]["attributes"]["last_analysis_stats"]   # ← спускаемся по ящикам к итогам проверки

    print(f"\nРезультат для {target}:")
    print(f"  Опасно:        {stats['malicious']}")    # ← сколько антивирусов считают объект вредоносным
    print(f"  Подозрительно: {stats['suspicious']}")   # ← сколько сомневаются
    print(f"  Безопасно:     {stats['harmless']}")     # ← сколько считают чистым
    print(f"  Нет данных:    {stats['undetected']}")   # ← сколько ничего не знают

    if stats["malicious"] >= 3:                        # ← 3 и больше «опасно» — уже не случайность
        print("Вердикт: ОПАСНО")
    elif stats["malicious"] > 0 or stats["suspicious"] > 0:   # ← 1–2 срабатывания: возможно, ложная тревога
        print("Вердикт: подозрительно, стоит присмотреться")
    else:                                              # ← ни того ни другого
        print("Вердикт: угроз не найдено")
elif response.status_code == 401:                      # ← пропуск не подошёл
    print("Ошибка: неверный API-ключ")
elif response.status_code == 404:                      # ← VirusTotal не знает такой адрес
    print("Ошибка: такой IP или домен не найден")
elif response.status_code == 429:                      # ← слишком часто (бесплатно — 4 запроса в минуту)
    print("Ошибка: превышен лимит запросов, подождите минуту")
else:                                                  # ← любой другой код
    print(f"Неожиданный ответ сервера: {response.status_code}")
