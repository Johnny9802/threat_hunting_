"""Database management for Sigma Translator module using SQLite."""
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from .models import Profile, FieldMapping, SigmaConversion, SigmaSetting, ConversionType, MappingStatus
from .config import sigma_settings


class SigmaDatabase:
    """SQLite database manager for Sigma Translator."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or sigma_settings.DATABASE_URL.replace("sqlite:///", "")
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Profiles table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sigma_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    index_name TEXT DEFAULT '*',
                    sourcetype TEXT,
                    cim_enabled INTEGER DEFAULT 0,
                    is_default INTEGER DEFAULT 0,
                    macros TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Field mappings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sigma_field_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id INTEGER NOT NULL,
                    sigma_field TEXT NOT NULL,
                    target_field TEXT NOT NULL,
                    status TEXT DEFAULT 'ok',
                    category TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (profile_id) REFERENCES sigma_profiles(id) ON DELETE CASCADE
                )
            """)

            # Conversions history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sigma_conversions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    conversion_type TEXT NOT NULL,
                    profile_id INTEGER,
                    input_content TEXT NOT NULL,
                    output_sigma TEXT,
                    output_spl TEXT,
                    prerequisites TEXT,
                    gap_analysis TEXT,
                    health_checks TEXT,
                    correlation_notes TEXT,
                    llm_used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (profile_id) REFERENCES sigma_profiles(id)
                )
            """)

            # Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sigma_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_mappings_profile ON sigma_field_mappings(profile_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_mappings_field ON sigma_field_mappings(sigma_field)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conversions_type ON sigma_conversions(conversion_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conversions_name ON sigma_conversions(name)")

            conn.commit()

            # Seed default profile if none exists
            cursor.execute("SELECT COUNT(*) FROM sigma_profiles")
            if cursor.fetchone()[0] == 0:
                self._seed_default_profiles(cursor)
                conn.commit()

    def _seed_default_profiles(self, cursor):
        """Create default profiles."""
        # Default Sysmon profile
        cursor.execute("""
            INSERT INTO sigma_profiles (name, description, index_name, sourcetype, cim_enabled, is_default)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "Default (Windows Sysmon)",
            "Default profile for Windows Sysmon logs",
            "windows",
            "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            0,
            1
        ))
        default_id = cursor.lastrowid

        # Default field mappings
        default_mappings = [
            ("CommandLine", "CommandLine", "process_creation"),
            ("Image", "Image", "process_creation"),
            ("ParentImage", "ParentImage", "process_creation"),
            ("ParentCommandLine", "ParentCommandLine", "process_creation"),
            ("User", "User", "process_creation"),
            ("ProcessId", "ProcessId", "process_creation"),
            ("ParentProcessId", "ParentProcessId", "process_creation"),
            ("CurrentDirectory", "CurrentDirectory", "process_creation"),
            ("IntegrityLevel", "IntegrityLevel", "process_creation"),
            ("Hashes", "Hashes", "process_creation"),
            ("OriginalFileName", "OriginalFileName", "process_creation"),
            ("TargetFilename", "TargetFilename", "file_event"),
            ("SourceFilename", "SourceFilename", "file_event"),
            ("DestinationIp", "DestinationIp", "network_connection"),
            ("DestinationPort", "DestinationPort", "network_connection"),
            ("SourceIp", "SourceIp", "network_connection"),
            ("SourcePort", "SourcePort", "network_connection"),
            ("DestinationHostname", "DestinationHostname", "network_connection"),
            ("Protocol", "Protocol", "network_connection"),
            ("TargetObject", "TargetObject", "registry_event"),
            ("Details", "Details", "registry_event"),
            ("QueryName", "QueryName", "dns_query"),
            ("QueryResults", "QueryResults", "dns_query"),
            ("ScriptBlockText", "ScriptBlockText", "powershell"),
        ]

        for sigma_field, target_field, category in default_mappings:
            cursor.execute("""
                INSERT INTO sigma_field_mappings (profile_id, sigma_field, target_field, status, category)
                VALUES (?, ?, ?, ?, ?)
            """, (default_id, sigma_field, target_field, "ok", category))

        # CIM profile
        cursor.execute("""
            INSERT INTO sigma_profiles (name, description, index_name, sourcetype, cim_enabled, is_default)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "Splunk CIM",
            "Splunk Common Information Model field names",
            "*",
            "*",
            1,
            0
        ))
        cim_id = cursor.lastrowid

        # CIM field mappings
        cim_mappings = [
            ("CommandLine", "process_command_line", "process_creation"),
            ("Image", "process_path", "process_creation"),
            ("ParentImage", "parent_process_path", "process_creation"),
            ("ParentCommandLine", "parent_process_command_line", "process_creation"),
            ("User", "user", "process_creation"),
            ("ProcessId", "process_id", "process_creation"),
            ("ParentProcessId", "parent_process_id", "process_creation"),
            ("TargetFilename", "file_path", "file_event"),
            ("DestinationIp", "dest_ip", "network_connection"),
            ("DestinationPort", "dest_port", "network_connection"),
            ("SourceIp", "src_ip", "network_connection"),
            ("SourcePort", "src_port", "network_connection"),
            ("TargetUserName", "user", "authentication"),
            ("IpAddress", "src_ip", "authentication"),
        ]

        for sigma_field, target_field, category in cim_mappings:
            cursor.execute("""
                INSERT INTO sigma_field_mappings (profile_id, sigma_field, target_field, status, category)
                VALUES (?, ?, ?, ?, ?)
            """, (cim_id, sigma_field, target_field, "ok", category))

    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # Profile CRUD operations
    def get_profiles(self) -> List[Profile]:
        """Get all profiles."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sigma_profiles ORDER BY is_default DESC, name")
            rows = cursor.fetchall()
            return [self._row_to_profile(row) for row in rows]

    def get_profile(self, profile_id: int) -> Optional[Profile]:
        """Get profile by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sigma_profiles WHERE id = ?", (profile_id,))
            row = cursor.fetchone()
            return self._row_to_profile(row) if row else None

    def get_default_profile(self) -> Optional[Profile]:
        """Get default profile."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sigma_profiles WHERE is_default = 1")
            row = cursor.fetchone()
            return self._row_to_profile(row) if row else None

    def create_profile(self, profile: Profile) -> Profile:
        """Create a new profile."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sigma_profiles (name, description, index_name, sourcetype, cim_enabled, is_default, macros)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.name,
                profile.description,
                profile.index_name,
                profile.sourcetype,
                1 if profile.cim_enabled else 0,
                1 if profile.is_default else 0,
                profile.macros
            ))
            conn.commit()
            profile.id = cursor.lastrowid
            return profile

    def update_profile(self, profile_id: int, updates: Dict[str, Any]) -> Optional[Profile]:
        """Update a profile."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
            values = list(updates.values()) + [profile_id]
            cursor.execute(f"UPDATE sigma_profiles SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
            conn.commit()
            return self.get_profile(profile_id)

    def delete_profile(self, profile_id: int) -> bool:
        """Delete a profile."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sigma_profiles WHERE id = ?", (profile_id,))
            conn.commit()
            return cursor.rowcount > 0

    # Field Mapping CRUD operations
    def get_mappings_for_profile(self, profile_id: int) -> List[FieldMapping]:
        """Get all mappings for a profile."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sigma_field_mappings WHERE profile_id = ? ORDER BY sigma_field", (profile_id,))
            rows = cursor.fetchall()
            return [self._row_to_mapping(row) for row in rows]

    def get_mappings_dict(self, profile_id: int) -> Dict[str, str]:
        """Get mappings as a dictionary."""
        mappings = self.get_mappings_for_profile(profile_id)
        return {m.sigma_field: m.target_field for m in mappings}

    def create_mapping(self, mapping: FieldMapping) -> FieldMapping:
        """Create a new field mapping."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sigma_field_mappings (profile_id, sigma_field, target_field, status, category, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                mapping.profile_id,
                mapping.sigma_field,
                mapping.target_field,
                mapping.status.value if isinstance(mapping.status, MappingStatus) else mapping.status,
                mapping.category,
                mapping.notes
            ))
            conn.commit()
            mapping.id = cursor.lastrowid
            return mapping

    def update_mapping(self, mapping_id: int, updates: Dict[str, Any]) -> Optional[FieldMapping]:
        """Update a field mapping."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
            values = list(updates.values()) + [mapping_id]
            cursor.execute(f"UPDATE sigma_field_mappings SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
            conn.commit()
            cursor.execute("SELECT * FROM sigma_field_mappings WHERE id = ?", (mapping_id,))
            row = cursor.fetchone()
            return self._row_to_mapping(row) if row else None

    def delete_mapping(self, mapping_id: int) -> bool:
        """Delete a field mapping."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sigma_field_mappings WHERE id = ?", (mapping_id,))
            conn.commit()
            return cursor.rowcount > 0

    def bulk_import_mappings(self, profile_id: int, mappings: List[FieldMapping]) -> int:
        """Bulk import mappings for a profile."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Delete existing mappings
            cursor.execute("DELETE FROM sigma_field_mappings WHERE profile_id = ?", (profile_id,))
            # Insert new mappings
            for mapping in mappings:
                cursor.execute("""
                    INSERT INTO sigma_field_mappings (profile_id, sigma_field, target_field, status, category, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    profile_id,
                    mapping.sigma_field,
                    mapping.target_field,
                    mapping.status.value if isinstance(mapping.status, MappingStatus) else mapping.status,
                    mapping.category,
                    mapping.notes
                ))
            conn.commit()
            return len(mappings)

    # Conversion History operations
    def get_conversions(self, limit: int = 50, offset: int = 0, conversion_type: Optional[str] = None) -> List[SigmaConversion]:
        """Get conversion history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if conversion_type:
                cursor.execute("""
                    SELECT * FROM sigma_conversions
                    WHERE conversion_type = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (conversion_type, limit, offset))
            else:
                cursor.execute("""
                    SELECT * FROM sigma_conversions
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            rows = cursor.fetchall()
            return [self._row_to_conversion(row) for row in rows]

    def get_conversion(self, conversion_id: int) -> Optional[SigmaConversion]:
        """Get a specific conversion."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sigma_conversions WHERE id = ?", (conversion_id,))
            row = cursor.fetchone()
            return self._row_to_conversion(row) if row else None

    def save_conversion(self, conversion: SigmaConversion) -> SigmaConversion:
        """Save a conversion to history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sigma_conversions
                (name, conversion_type, profile_id, input_content, output_sigma, output_spl,
                 prerequisites, gap_analysis, health_checks, correlation_notes, llm_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                conversion.name,
                conversion.conversion_type.value if isinstance(conversion.conversion_type, ConversionType) else conversion.conversion_type,
                conversion.profile_id,
                conversion.input_content,
                conversion.output_sigma,
                conversion.output_spl,
                conversion.prerequisites,
                conversion.gap_analysis,
                conversion.health_checks,
                conversion.correlation_notes,
                1 if conversion.llm_used else 0
            ))
            conn.commit()
            conversion.id = cursor.lastrowid
            return conversion

    def delete_conversion(self, conversion_id: int) -> bool:
        """Delete a conversion."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sigma_conversions WHERE id = ?", (conversion_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_old_conversions(self, days: int) -> int:
        """Delete conversions older than specified days."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM sigma_conversions
                WHERE created_at < datetime('now', '-' || ? || ' days')
            """, (days,))
            conn.commit()
            return cursor.rowcount

    def get_conversion_stats(self) -> Dict[str, Any]:
        """Get conversion statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sigma_conversions")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT conversion_type, COUNT(*) FROM sigma_conversions GROUP BY conversion_type")
            by_type = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.execute("SELECT COUNT(*) FROM sigma_conversions WHERE llm_used = 1")
            llm_count = cursor.fetchone()[0]
            return {
                "total": total,
                "by_type": by_type,
                "llm_used": llm_count
            }

    # Helper methods
    def _row_to_profile(self, row: sqlite3.Row) -> Profile:
        """Convert database row to Profile object."""
        return Profile(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            index_name=row["index_name"],
            sourcetype=row["sourcetype"],
            cim_enabled=bool(row["cim_enabled"]),
            is_default=bool(row["is_default"]),
            macros=row["macros"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
        )

    def _row_to_mapping(self, row: sqlite3.Row) -> FieldMapping:
        """Convert database row to FieldMapping object."""
        return FieldMapping(
            id=row["id"],
            profile_id=row["profile_id"],
            sigma_field=row["sigma_field"],
            target_field=row["target_field"],
            status=MappingStatus(row["status"]) if row["status"] else MappingStatus.OK,
            category=row["category"],
            notes=row["notes"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
        )

    def _row_to_conversion(self, row: sqlite3.Row) -> SigmaConversion:
        """Convert database row to SigmaConversion object."""
        return SigmaConversion(
            id=row["id"],
            name=row["name"],
            conversion_type=ConversionType(row["conversion_type"]) if row["conversion_type"] else ConversionType.SIGMA_TO_SPL,
            profile_id=row["profile_id"],
            input_content=row["input_content"],
            output_sigma=row["output_sigma"],
            output_spl=row["output_spl"],
            prerequisites=row["prerequisites"],
            gap_analysis=row["gap_analysis"],
            health_checks=row["health_checks"],
            correlation_notes=row["correlation_notes"],
            llm_used=bool(row["llm_used"]),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
        )


# Singleton instance
sigma_db = SigmaDatabase()
