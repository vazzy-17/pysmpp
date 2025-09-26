import smpplib.client
import smpplib.consts
import logging
import time

# Logging setup
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

def handle_deliver_sm(pdu):
    logging.info("📩 Received deliver_sm:")
    logging.info(f"  From: {pdu.source_addr}")
    logging.info(f"  To: {pdu.destination_addr}")
    logging.info(f"  Message: {pdu.short_message}")
    logging.info(f"  Command Status: {pdu.status}")
    logging.info(f"  Message ID: {pdu.message_id if hasattr(pdu, 'message_id') else 'N/A'}")

# Inisialisasi client
# client = smpplib.client.Client('sms-gw.aurateknologi.com', 37002)
client = smpplib.client.Client('127.0.0.1', 37002)
client.set_message_received_handler(handle_deliver_sm)

# Connect & bind
client.connect()
# client.bind_transceiver(system_id='dwi_test', password='123456')
client.bind_transceiver(system_id='dwi_test', password='123456')
logging.info("✅ Bind berhasil")

# Kirim SMS (UCS2)
message_text = "test dari python 25 september 2"
pdu = client.send_message(
    source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
    source_addr_npi=0,
    source_addr='YesDok',
    dest_addr_ton=1,
    dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
    destination_addr='6289630489151',
    short_message=message_text.encode('utf-16-be'),
    data_coding=8,    # UCS2
    esm_class=0,      # Normal message
    registered_delivery=True,
)
logging.info(f"📨 Sent message, PDU seq: {pdu.sequence}, Message ID: {getattr(pdu, 'message_id', 'N/A')}")

# Loop untuk menerima DLR (deliver_sm)
timeout = time.time() + 150
while time.time() < timeout:
    client.read_once()
    time.sleep(1)

client.unbind()
client.disconnect()
logging.info("✅ Client disconnected")
