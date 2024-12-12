import ssl
import socket
import hashlib


def get_cert_public_key_hash(hostname, port=443):
    # Створення SSL контексту
    context = ssl.create_default_context()

    # Підключення до сервера через TLS
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Отримання сертифіката
            cert = ssock.getpeercert()

            # Отримання публічного ключа з сертифіката
            pubkey = ssock.getpeercert(binary_form=True)

            # Обчислення хешу публічного ключа (SHA-256)
            pubkey_hash = hashlib.sha256(pubkey).hexdigest()

            # Перевірка дійсності сертифіката
            try:
                # Встановлення режиму перевірки сертифіката
                context.verify_mode = ssl.CERT_REQUIRED  # Перевіряємо сертифікат і домен
                context.check_hostname = True
                # Викидається помилка, якщо сертифікат не підходить
                ssock.getpeercert()
                print("SSL сертифікат валідний")
            except ssl.CertificateError as e:
                print("Помилка сертифіката:", e)

            return pubkey_hash


if __name__ == "__main__":
    # Отримання адреси вебсайту від користувача через консоль
    hostname = input("Введіть адресу вебсайту (наприклад, www.example.com): ")

    # Виклик функції для отримання хешу публічного ключа
    pubkey_hash = get_cert_public_key_hash(hostname)

    # Виведення хешу публічного ключа
    print(f"Хеш публічного ключа: {pubkey_hash}")
