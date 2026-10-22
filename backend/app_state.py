from backend.authentication import DeviceAuthenticator
from backend.secure_communication import SecureCommunication
from backend.encryption import DataEncryption
from backend.server_receiver import ServerReceiver
from backend.ids_monitor import IDSMonitor


class SecureGuardState:

    def __init__(self):
        self.authenticator = DeviceAuthenticator()
        self.communication = SecureCommunication()
        self.encryption = DataEncryption()

        self.receiver = ServerReceiver(
            self.authenticator,
            self.communication,
            self.encryption
        )

        self.ids_monitor = IDSMonitor()

        # Accepted healthcare readings
        self.readings = []

        # Rejected device messages
        self.blocked_attacks = []


# Shared state for components running in the same Python process
state = SecureGuardState()