class FileIO:
    @staticmethod
    def read_input_file(filename):
        with open(filename, 'rb') as f:
            return list(f.read())

    @staticmethod
    def write_output_file(data, filename):
        with open(filename, 'wb') as f:
            f.write(bytes(data))

    @staticmethod
    def write_text_file(data, filename):
        with open(filename, 'w') as f:
            for value in data:
                f.write(f"{value}\n")