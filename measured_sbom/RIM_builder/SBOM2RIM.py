import sqlite3
from cyclonedx.parser import XmlParser
from cyclonedx.model.component import Component
from cyclonedx.model.hash import HashAlgorithm
from typing import Optional, List

# Import the generated protobuf classes
import rim_pb2

# Constants
DEFAULT_CONTROLLER_NAME = 'Unknown Controller'
DATABASE_PATH = 'rim_database.db'

# Function to calculate the integrity measurement of a component using SHA-256
def calculate_integrity(component: Component) -> Optional[str]:
    """
    Calculates the SHA-256 integrity measurement of a component.
    Returns the hash if found, else None.
    """
    for component_hash in component.hashes or []:
        if component_hash.alg == HashAlgorithm.SHA_256:
            return component_hash.content
    return None

# Function to parse SBOM file and create a list of RIMManifest entries
def parse_sbom_to_rim_manifest(sbom_file_path: str, controller_id: int) -> List[rim_pb2.RIMManifest]:
    """
    Parses an SBOM XML file to create RIMManifest entries for the components listed in the SBOM.
    Associates these entries with the given controller ID.
    """
    with open(sbom_file_path, 'r', encoding='utf-8') as sbom_file:
        parser = XmlParser(sbom_file.read())
    
    bom = parser.get_bom()
    rim_manifests: List[rim_pb2.RIMManifest] = []

    # Iterate over components in the SBOM and create corresponding RIMManifest entries
    for component in bom.components or []:
        integrity_measurement = calculate_integrity(component)
        if integrity_measurement:
            # Create and populate the RIMManifest
            rim_manifest = rim_pb2.RIMManifest(
                tag_id=component.bom_ref,  # Using BOM reference as tag_id
                version=component.version,
                platform_model=component.name
            )

            # Add payload element with integrity measurement
            payload = rim_pb2.PayloadElement(
                name=component.name,
                version=component.version,
                size=component.size if component.size else 0,
                hash=integrity_measurement
            )
            rim_manifest.payload.append(payload)
            rim_manifests.append(rim_manifest)

    return rim_manifests

# Function to initialize the database and ensure required tables are created
def initialize_database(db_path: str):
    """
    Initializes the SQLite database and creates tables if they do not exist.
    """
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Create table for controllers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS controllers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        ''')

        # Create table for RIM manifests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rim_manifests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                controller_id INTEGER NOT NULL,
                rim_manifest BLOB NOT NULL,
                FOREIGN KEY (controller_id) REFERENCES controllers(id)
            )
        ''')
        conn.commit()

# Function to verify or add a controller to the database
def add_or_verify_controller(db_path: str, controller_id: int, controller_name: str = DEFAULT_CONTROLLER_NAME):
    """
    Ensures the controller exists in the database. If not, it adds the controller.
    """
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Check if the controller already exists
        cursor.execute('SELECT id FROM controllers WHERE id = ?', (controller_id,))
        result = cursor.fetchone()

        if not result:
            # Insert the controller if it doesn't exist
            cursor.execute('''
                INSERT INTO controllers (id, name)
                VALUES (?, ?)
            ''', (controller_id, controller_name))
            conn.commit()

# Function to store RIM manifests into the database
def store_rim_manifests(db_path: str, rim_manifests: List[rim_pb2.RIMManifest]):
    """
    Stores a list of RIMManifest entries into the database, serialized as binary data.
    """
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        for manifest in rim_manifests:
            rim_manifest_bytes = manifest.SerializeToString()

            cursor.execute('''
                INSERT INTO rim_manifests (controller_id, rim_manifest)
                VALUES (?, ?)
            ''', (1, rim_manifest_bytes))  # Assuming controller_id=1 for simplicity
        conn.commit()

# Function to retrieve and deserialize RIM manifests from the database
def retrieve_rim_manifests(db_path: str, controller_id: int) -> List[rim_pb2.RIMManifest]:
    """
    Retrieves and deserializes RIM manifests from the database for a given controller ID.
    """
    rim_manifests: List[rim_pb2.RIMManifest] = []

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT rim_manifest FROM rim_manifests WHERE controller_id = ?
        ''', (controller_id,))

        for row in cursor.fetchall():
            rim_manifest_bytes = row[0]
            rim_manifest = rim_pb2.RIMManifest()
            rim_manifest.ParseFromString(rim_manifest_bytes)
            rim_manifests.append(rim_manifest)

    return rim_manifests

# Main function: Orchestrates the process from SBOM parsing to database storage
def main():
    sbom_file_path = 'sbom.xml'  # Path to the CycloneDX SBOM file
    db_path = DATABASE_PATH      # Path to the SQLite database file
    controller_id = 1            # Controller ID to associate with the RIMManifest entries
    controller_name = 'Controller A'  # Name of the controller

    # Initialize the database and ensure tables are created
    initialize_database(db_path)

    # Add or verify the existence of the controller in the database
    add_or_verify_controller(db_path, controller_id, controller_name)

    # Parse the SBOM and create RIMManifest entries
    rim_manifests = parse_sbom_to_rim_manifest(sbom_file_path, controller_id)

    # Store the RIMManifest entries into the database
    store_rim_manifests(db_path, rim_manifests)

    print(f"Successfully stored {len(rim_manifests)} RIM manifests for controller ID {controller_id} into the database.")

    # Example: Retrieve and display stored RIM manifests
    retrieved_manifests = retrieve_rim_manifests(db_path, controller_id)
    for manifest in retrieved_manifests:
        print(f"Tag ID: {manifest.tag_id}, Version: {manifest.version}, Platform Model: {manifest.platform_model}")

if __name__ == '__main__':
    main()