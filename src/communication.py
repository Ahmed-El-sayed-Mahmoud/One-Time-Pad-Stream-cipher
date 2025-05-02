class Communication:
    """
    Handles simulated communication between sender and receiver using a file.
    """

    def __init__(self, filepath='transmission.bin'):
        self.filepath = filepath

    def send(self, text):
        """
        Simulate sending by writing data to a file.
        """
        with open(self.filepath, 'wb') as f:
            f.write(text)

    def receive(self):
        """
        Simulate receiving by reading data from a file.
        """
        with open(self.filepath, 'rb') as f:
            return f.read()
