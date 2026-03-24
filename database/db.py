import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path="ids_database.db"):
        self.db_path = db_path
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def init_database(self):
        """Create database tables if they don't exist"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    description TEXT,
                    raw_data TEXT
                )
            ''')

            # System logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT,
                    status TEXT
                )
            ''')

            # Traffic statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    protocol TEXT
                )
            ''')

            conn.commit()

    def insert_alert(self, alert_data):
        """Insert an alert into the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts 
                (timestamp, alert_type, severity, source_ip, destination_ip, 
                 source_port, destination_port, protocol, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                alert_data.get('alert_type', 'Unknown'),
                alert_data.get('severity', 'Medium'),
                alert_data.get('source_ip'),
                alert_data.get('destination_ip'),
                alert_data.get('source_port'),
                alert_data.get('destination_port'),
                alert_data.get('protocol'),
                alert_data.get('description'),
                alert_data.get('raw_data')
            ))
            conn.commit()

    def insert_system_log(self, event_type, message, status="INFO"):
        """Insert a system event log"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO system_logs (timestamp, event_type, message, status)
                VALUES (?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                message,
                status
            ))
            conn.commit()

    def insert_traffic_stat(self, traffic_data):
        """Insert traffic statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO traffic_stats 
                (timestamp, source_ip, destination_ip, packet_count, byte_count, protocol)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                traffic_data.get('source_ip'),
                traffic_data.get('destination_ip'),
                traffic_data.get('packet_count', 0),
                traffic_data.get('byte_count', 0),
                traffic_data.get('protocol')
            ))
            conn.commit()

    def get_all_alerts(self, limit=100):
        """Fetch all alerts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return cursor.fetchall()

    def get_alerts_by_severity(self, severity, limit=100):
        """Fetch alerts by severity level"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM alerts WHERE severity = ? 
                ORDER BY timestamp DESC LIMIT ?
            ''', (severity, limit))
            return cursor.fetchall()

    def get_system_logs(self, limit=100):
        """Fetch system logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return cursor.fetchall()

    def get_traffic_stats(self, limit=100):
        """Fetch traffic statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM traffic_stats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return cursor.fetchall()

    def get_alert_count(self):
        """Get total alert count"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM alerts')
            return cursor.fetchone()['count']

    def get_high_severity_count(self):
        """Get count of high severity alerts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as count FROM alerts WHERE severity = 'High'
            ''')
            return cursor.fetchone()['count']

    def delete_old_records(self, days=30):
        """Delete records older than specified days"""
        from datetime import timedelta
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_date,))
            cursor.execute('DELETE FROM system_logs WHERE timestamp < ?', (cutoff_date,))
            cursor.execute('DELETE FROM traffic_stats WHERE timestamp < ?', (cutoff_date,))
            conn.commit()