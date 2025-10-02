import smpplib.client
import smpplib.consts
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid

# Setup logging
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s | %(levelname)-8s | %(threadName)-10s | %(message)s',
    datefmt='%H:%M:%S'
)

# Global variables untuk tracking
dlr_tracker = {}
tracker_lock = threading.Lock()
sent_messages = 0
received_dlrs = 0

class DLRClient:
    def __init__(self, host, port, system_id, password):
        self.client = smpplib.client.Client(host, port)
        self.system_id = system_id
        self.password = password
        self.connected = False
        
        # Setup handlers
        self.client.set_message_received_handler(self._handle_deliver_sm)
        self.client.set_message_sent_handler(self._handle_message_sent)
        
    def _handle_deliver_sm(self, pdu):
        """Handle deliver_sm (DLR)"""
        global received_dlrs
        
        try:
            logging.info(f"📩 DLR RECEIVED - Command: {pdu.command}")
            
            # Untuk DLR, short_message berisi data DLR
            short_message = pdu.short_message
            if isinstance(short_message, bytes):
                short_message = short_message.decode('utf-8', errors='ignore')
            
            logging.info(f"📨 Raw DLR content: {short_message}")
            
            # Parse DLR fields
            fields = {}
            for item in short_message.split():
                if ':' in item:
                    key, value = item.split(':', 1)
                    fields[key] = value
            
            # Extract DLR information
            msg_id = fields.get('id', 'Unknown')
            status = fields.get('stat', 'UNKNOWN')
            
            logging.info(f"🆔 DLR Details - Message ID: {msg_id}, Status: {status}")
            
            # Update tracker
            with tracker_lock:
                # Cari message_id di tracker
                for track_id, info in dlr_tracker.items():
                    if info.get('smsc_message_id') == msg_id or track_id in msg_id:
                        dlr_tracker[track_id]['status'] = status
                        dlr_tracker[track_id]['received_at'] = time.time()
                        received_dlrs += 1
                        logging.info(f"✅ DLR MATCHED - Track ID: {track_id}, Status: {status}")
                        break
                else:
                    logging.warning(f"❓ UNKNOWN DLR - Message ID: {msg_id}")
                    
        except Exception as e:
            logging.error(f"❌ Error processing DLR: {e}")
            import traceback
            logging.error(traceback.format_exc())

    def _handle_message_sent(self, pdu):
        """Handle ketika message berhasil dikirim"""
        if pdu.command == 'submit_sm_resp':
            message_id = getattr(pdu, 'message_id', None)
            sequence = getattr(pdu, 'sequence', None)
            if message_id:
                logging.info(f"📤 MESSAGE SENT - Sequence: {sequence}, SMSC Message ID: {message_id}")

    def connect_and_bind(self):
        """Connect dan bind ke server"""
        try:
            self.client.connect()
            self.client.bind_transceiver(
                system_id=self.system_id, 
                password=self.password
            )
            self.connected = True
            logging.info("✅ Bind berhasil sebagai transceiver")
            return True
        except Exception as e:
            logging.error(f"❌ Bind failed: {e}")
            return False

    def send_single_message(self, message_id, phone_number, message_text, thread_num):
        """Kirim single message"""
        global sent_messages
        
        if not self.connected:
            logging.error(f"❌ Client not connected - Thread {thread_num}")
            return False
            
        try:
            logging.info(f"📤 SENDING [{thread_num}] - ID: {message_id} to {phone_number}")
            
            # Kirim message
            pdu = self.client.send_message(
                source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
                source_addr_npi=smpplib.consts.SMPP_NPI_ISDN, 
                source_addr='YesDok',
                dest_addr_ton=1,
                dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                destination_addr=phone_number,
                short_message=message_text.encode('utf-8'),
                data_coding=0,
                esm_class=0,
                registered_delivery=True,  # Penting untuk DLR
            )
            
            # Dapatkan message_id dari response
            smsc_message_id = getattr(pdu, 'message_id', f'thread-{thread_num}')
            
            with tracker_lock:
                dlr_tracker[message_id] = {
                    'smsc_message_id': smsc_message_id,
                    'phone_number': phone_number,
                    'thread_num': thread_num,
                    'sent_at': time.time(),
                    'status': 'SENT',
                    'received_at': None
                }
                sent_messages += 1
            
            logging.info(f"✅ SENT [{thread_num}] - ID: {message_id}, SMSC-ID: {smsc_message_id}")
            return True
            
        except Exception as e:
            logging.error(f"❌ FAILED [{thread_num}] - ID: {message_id}, Error: {e}")
            with tracker_lock:
                dlr_tracker[message_id] = {
                    'phone_number': phone_number,
                    'thread_num': thread_num,
                    'sent_at': time.time(),
                    'status': 'FAILED',
                    'error': str(e)
                }
            return False

    def start_listener(self):
        """Start listener untuk menerima DLR"""
        def listen():
            while self.connected:
                try:
                    # Listen for incoming PDUs (termasuk DLR)
                    self.client.read_once()
                    time.sleep(0.1)
                except Exception as e:
                    if self.connected:
                        logging.error(f"❌ Listener error: {e}")
                    break
        
        listener_thread = threading.Thread(target=listen, name="DLR-Listener", daemon=True)
        listener_thread.start()
        logging.info("🎧 DLR listener started")

    def disconnect(self):
        """Disconnect dari server"""
        self.connected = False
        try:
            self.client.unbind()
            self.client.disconnect()
            logging.info("✅ Disconnected from SMSC")
        except:
            pass

def send_concurrent_messages():
    """Kirim 10 messages secara concurrent"""
    client = DLRClient('127.0.0.1', 37002, 'dwi_test', '123456')
    
    if not client.connect_and_bind():
        return None
    
    # Start DLR listener
    client.start_listener()
    
    try:
        # Data untuk 10 messages
        messages = []
        for i in range(10):
            message_id = str(uuid.uuid4())[:8]
            phone_number = f'6289630489{i:03d}'
            message_text = f'Test message #{i+1} from Python SMPP - ID: {message_id}'
            
            messages.append({
                'message_id': message_id,
                'phone_number': phone_number,
                'message_text': message_text,
                'thread_num': i+1
            })
        
        # Kirim secara concurrent
        start_time = time.time()
        logging.info("🚀 Starting concurrent message sending...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_msg = {
                executor.submit(
                    client.send_single_message, 
                    msg['message_id'], 
                    msg['phone_number'], 
                    msg['message_text'], 
                    msg['thread_num']
                ): msg['message_id'] for msg in messages
            }
            
            for future in as_completed(future_to_msg):
                msg_id = future_to_msg[future]
                try:
                    success = future.result()
                    if not success:
                        logging.error(f"⚠️ Message {msg_id} failed to send")
                except Exception as e:
                    logging.error(f"💥 Exception for {msg_id}: {e}")
        
        send_duration = time.time() - start_time
        logging.info(f"⏰ All messages sent in {send_duration:.2f} seconds")
        
        return client
        
    except Exception as e:
        logging.error(f"❌ Sending error: {e}")
        client.disconnect()
        return None

def monitor_dlr_progress(timeout=60):
    """Monitor progress DLR"""
    global sent_messages, received_dlrs
    
    start_time = time.time()
    last_report_time = start_time
    
    logging.info("🔍 Starting DLR monitoring...")
    
    while time.time() - start_time < timeout:
        current_time = time.time()
        
        # Report progress setiap 5 detik
        if current_time - last_report_time >= 5:
            with tracker_lock:
                pending = sent_messages - received_dlrs
                success_count = sum(1 for msg in dlr_tracker.values() if msg.get('status') in ['DELIVRD', 'ACCEPTD', 'DELIVERED'])
                failed_count = sum(1 for msg in dlr_tracker.values() if msg.get('status') in ['UNDELIV', 'REJECTD', 'EXPIRED', 'FAILED'])
                unknown_count = sum(1 for msg in dlr_tracker.values() if msg.get('status') == 'SENT')
            
            logging.info(f"📊 PROGRESS - Sent: {sent_messages}, DLRs: {received_dlrs}, "
                        f"Pending: {pending}, Success: {success_count}, Failed: {failed_count}, Unknown: {unknown_count}")
            
            # Print detail DLRs yang sudah diterima
            if received_dlrs > 0:
                for msg_id, info in dlr_tracker.items():
                    if info.get('received_at'):
                        logging.info(f"   📩 {msg_id} -> {info.get('status')}")
            
            last_report_time = current_time
        
        # Jika semua DLR sudah diterima, keluar lebih awal
        with tracker_lock:
            if received_dlrs >= sent_messages and sent_messages > 0:
                logging.info("🎯 All DLRs received!")
                break
        
        time.sleep(1)
    
    return generate_final_report()

def generate_final_report():
    """Generate final report"""
    logging.info("=" * 60)
    logging.info("📋 FINAL REPORT")
    logging.info("=" * 60)
    
    with tracker_lock:
        total_sent = sent_messages
        total_dlrs = received_dlrs
        missing_dlrs = total_sent - total_dlrs
        
        status_count = {}
        for msg in dlr_tracker.values():
            status = msg.get('status', 'UNKNOWN')
            status_count[status] = status_count.get(status, 0) + 1
        
        logging.info(f"Total Messages Sent: {total_sent}")
        logging.info(f"Total DLRs Received: {total_dlrs}")
        logging.info(f"Missing DLRs: {missing_dlrs}")
        logging.info("")
        logging.info("Status Breakdown:")
        for status, count in status_count.items():
            logging.info(f"  {status}: {count}")
        
        if missing_dlrs > 0:
            logging.info("")
            logging.info("❌ Messages with missing DLRs:")
            for msg_id, info in dlr_tracker.items():
                if info.get('status') == 'SENT' and info.get('received_at') is None:
                    logging.info(f"  - {msg_id} to {info.get('phone_number', 'N/A')}")
    
    return total_sent, total_dlrs

def main():
    """Main function"""
    try:
        # Kirim messages
        client = send_concurrent_messages()
        if not client:
            logging.error("❌ Failed to send messages")
            return
        
        # Monitor DLRs
        total_sent, total_dlrs = monitor_dlr_progress(timeout=60)
        
        # Final check
        if total_sent == total_dlrs:
            logging.info("🎉 SUCCESS: All DLRs received!")
        else:
            logging.warning(f"⚠️ INCOMPLETE: {total_sent - total_dlrs} DLRs missing")
        
    except KeyboardInterrupt:
        logging.info("🛑 Dihentikan oleh user")
    except Exception as e:
        logging.error(f"💥 Unexpected error: {e}")
    finally:
        # Cleanup
        if 'client' in locals():
            client.disconnect()

if __name__ == "__main__":
    main()