import os
import virus_total
from elf_packer import ELFPacker
from random import Random

SEED = 100  # Seed value for random key - used for consistent results


class DetectionTest:
    def __init__(self, filename, original, packed):
        """
        Calculates and aggregates the results of a scan from VirusTotal of both an original and packed file.

        :param filename: The filename of the file being scanned
        :param original: The results from the scan of the original file
        :param packed: The results from the scan of the packed file
        """
        self.filename = filename
        self.original = original
        self.packed = packed

        # Get the most popular name of the virus if any exist
        self.name = self._get_most_popular_name()

        # Store the detection rates and calculate the benefit of packing
        self.original_detection_rate = self.get_original_detection_rate()
        self.packed_detection_rate = self.get_packed_detection_rate()
        self.benefit = self._get_benefit()

    def get_aggregated_results(self):
        """
        Gets a dict representation of the results of the scans.

        :return: A dict representing the detection rates
        """
        return {
            'name': self.name,
            'original': self.original_detection_rate,
            'packed': self.packed_detection_rate,
            'benefit': self.benefit
        }

    def get_original_detection_rate(self):
        """ Gets the aggregated results of the scan of the original file """
        return self._get_detection_rate('original')

    def get_packed_detection_rate(self):
        """ Gets the aggregated results of the scan of the packed file """
        return self._get_detection_rate('packed')

    def _get_detection_rate(self, key):
        """
        Gets the aggregated results of the scan of the file chosen.

        :param key: Either the packed or original result
        """
        option = self.original if key == 'original' else self.packed
        scanners = option.keys()
        total = len(scanners)
        detected = len([option[x] for x in scanners if option[x]['detected'] is True]) * 1.0

        return detected / total

    def _get_most_popular_name(self):
        """
        Returns the most popular name given to the binary if it is detected by one or more scanners.

        :return: A string containing the most popular name given to the scanned file.
        """
        scanners = self.original.keys()
        true_detections = [self.original[x] for x in scanners if self.original[x]['detected'] is True]
        names = {}
        for detection in true_detections:
            name = detection['result']
            if detection['result'] in names.keys():
                names[name] += 1
            else:
                names[name] = 1

        return next(iter([x for x in names if names[x] == max(names.values())]), None)

    def _get_benefit(self):
        """
        Calculate the benefit of running the packer over the binary.

        :return: A float representing the improvement of undetected rates of the binary.
        """
        orig = self.get_original_detection_rate()
        packed = self.get_packed_detection_rate()
        return (orig - packed) / orig if orig > 0 else 0


class TestRunner:
    def __init__(self, test_folder):
        """
        Instantiates a new TestRunner object, with a folder containing binaries to run tests on. This folder must
        contain two additional folders: bin and virus, which contain the regular binaries to test functionality and
        speed against, as well a viruses to compare against VirusTotal detection rates with.

        :param test_folder: The folder containing the binary files to test.
        """

        dirs = next(os.walk(test_folder))[1]
        diff = {'virus', 'bin'}.difference(set(dirs))
        if len(diff) > 0:
            raise AssertionError("The test folder must contain 'virus' and 'bin' subfolders containing test binaries")

        self.test_folder = test_folder

    def run_all_tests(self):
        """
        Runs all tests on binaries in the specified folder.
        """
        # Test packed vs non-packed viruses
        detection = self.test_detection()

        # Check speed for packed vs non-packed binaries
        speed = self.test_speed()

        # Check correctness for packed vs non-packed binaries
        correctness = self.test_correctness()

    def test_detection(self):
        virus_dir = os.path.join(self.test_folder, 'virus')

        # Clean up any already packed files
        print("[*] Cleaning up previously packed files")
        self._clean_packed_files(virus_dir)

        # Repack the rest of the files and scan each one
        print("[*] Encrypting and scanning")
        scan_results = self._get_detection_results(virus_dir)
        print("[*] Scanning complete")

        # Analyse the results
        aggregated = {}
        for scan in scan_results:
            aggregated[scan.filename] = scan.get_aggregated_results()

        return aggregated

    def test_speed(self):
        return None

    def test_correctness(self):
        return None

    @staticmethod
    def _get_detection_results(virus_dir):
        scan_results = []
        for root, _, files in os.walk(virus_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rnd = Random(SEED)
                key = rnd.randint(0, 100)
                try:
                    packer = ELFPacker(full_path)
                    all_functions = packer.list_functions()
                    packer.encrypt(key, all_functions)
                except Exception as ex:
                    print(f"Error encrypting {file}, skipping")
                    print(type(ex))
                    continue

                # Test each file and record the result
                original = virus_total.scan_file(full_path)['scans']
                packed = virus_total.scan_file(f"{full_path}.packed")['scans']
                scan_results.append(DetectionTest(file, original, packed))

        return scan_results

    @staticmethod
    def _clean_packed_files(folder):
        for root, _, files in os.walk(folder):
            for file in files:
                file = os.path.join(root, file)
                if file.endswith('packed'):
                    os.remove(file)
