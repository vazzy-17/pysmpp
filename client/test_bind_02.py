import smpplib.client
import smpplib.consts
import smpplib.gsm
import logging
import time
import threading

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

def smpp_client_worker(system_id, password, source_addr, destination_addr, message_text):
    logging.debug(f"[{system_id}] 🔧 Membuat SMPP client...")
    client = smpplib.client.Client('127.0.0.1', 2775)

    # Handler untuk DLR
    def handle_deliver_sm(pdu):
        msg = pdu.short_message
        if isinstance(msg, bytes):
            try:
                msg = msg.decode('utf-8')
            except:
                msg = msg.decode('latin1')
        logging.info(f"[{system_id}] 📩 Received deliver_sm:\n"
                     f"  From: {pdu.source_addr}\n"
                     f"  To: {pdu.destination_addr}\n"
                     f"  Message: {msg}\n"
                     f"  Status: {pdu.status}")

    client.set_message_received_handler(handle_deliver_sm)

    # Connect & Bind
    logging.debug(f"[{system_id}] 🔌 Connecting...")
    client.connect()
    logging.debug(f"[{system_id}] 🔑 Binding...")
    client.bind_transceiver(system_id=system_id, password=password)
    logging.info(f"[{system_id}] ✅ Bind sukses")

    # Bagi pesan jadi multipart
    parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(message_text)
    logging.debug(f"[{system_id}] ✉️ Multipart SMS: {len(parts)} bagian")

    # Kirim setiap part
    for idx, part in enumerate(parts, 1):
        logging.debug(f"[{system_id}] 📤 Kirim part {idx}/{len(parts)}")
        pdu = client.send_message(
            source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
            source_addr_npi=0,
            source_addr=source_addr,
            dest_addr_ton=1,
            dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            destination_addr=destination_addr,
            short_message=part,
            data_coding=encoding_flag,
            esm_class=msg_type_flag,
            registered_delivery=True,
        )
        logging.info(f"[{system_id}] 📨 Sent part {idx}, PDU seq: {pdu.sequence}")

    # Terima deliver_sm (DLR)
    timeout = time.time() + 30
    logging.debug(f"[{system_id}] ⏳ Tunggu DLR selama 30 detik...")
    while time.time() < timeout:
        client.read_once()
        time.sleep(0.5)

    # Unbind & Disconnect
    logging.debug(f"[{system_id}] 🔚 Unbind & disconnect")
    client.unbind()
    client.disconnect()
    logging.info(f"[{system_id}] ✅ Selesai")

# Pesan panjang agar multipart
long_message = (
    "Ini adalah pesan SMS yang sangat panjang, melebihi 160 karakter, sehingga akan dikirim sebagai multipart "
    "message. Setiap bagian pesan memiliki batasan tertentu sesuai standar GSM. Semoga bagian ini cukup panjang "
    "untuk membuktikan hal tersebut. Terima kasih sudah mencoba!"
)

# Jalankan 2 thread untuk 2 client
t1 = threading.Thread(
    target=smpp_client_worker,
    args=('test1', 'password1', 'YesDok1', '628123456789', long_message)
)
t2 = threading.Thread(
    target=smpp_client_worker,
    args=('test2', 'password', 'YesDok2', '628123456789', long_message)
)

t1.start()
t2.start()
t1.join()
t2.join()

logging.info("🎉 Semua client selesai")
