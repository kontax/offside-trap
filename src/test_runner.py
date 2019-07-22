import json
import os
from abc import ABC, abstractmethod
from random import Random
from shutil import copyfile
from subprocess import Popen, check_output, PIPE

import virus_total
from conf.test_binaries import TEST_BINARY_LIST
from elf_packer import ELFPacker

SEED = 100  # Seed value for random key - used for consistent results


class TestResult(ABC):
    def __init__(self, filename, original, packed):
        self.filename = filename
        self.original = original
        self.packed = packed

        # Store the detection rates and calculate the benefit of packing
        self.original_rate = self._get_original_rate()
        self.packed_rate = self._get_packed_rate()
        self.benefit = self._get_benefit()

        # Get any additional information
        self.info = self._get_info()

    def __str__(self):
        return json.dumps(self.get_aggregated_results(), indent=4, sort_keys=True)

    def get_aggregated_results(self):
        """
        Gets a dict representation of the results of the scans.

        :return: A dict representing the detection rates
        """
        return {
            'info': self.info,
            'original': self.original_rate,
            'packed': self.packed_rate,
            'benefit': self.benefit
        }

    @abstractmethod
    def _get_original_rate(self):
        pass

    @abstractmethod
    def _get_packed_rate(self):
        pass

    @abstractmethod
    def _get_benefit(self):
        pass

    @abstractmethod
    def _get_info(self):
        pass


class CorrectnessTestResult(TestResult):

    def __init__(self, filename, original, packed):
        super().__init__(filename, original, packed)

    def _get_original_rate(self):
        return 1.0

    def _get_packed_rate(self):
        correct = 0
        for key in self.packed.keys():
            if self.packed[key] == self.original[key]:
                correct += 1

        return correct / (len(self.packed.keys()) * 1.0)

    def _get_benefit(self):
        return self.packed_rate

    def _get_info(self):
        return None


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

        # Store the detection rates and calculate the benefit of packing
        self.original_detection_rate = self.get_original_rate()
        self.packed_detection_rate = self.get_packed_rate()
        self.benefit = self._get_benefit()

        # Get the most popular name of the virus if any exist
        self.name = self._get_most_popular_name()

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

    def get_original_rate(self):
        """ Gets the aggregated results of the scan of the original file """
        return self._get_detection_rate('original')

    def get_packed_rate(self):
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
        orig = self.get_original_rate()
        packed = self.get_packed_rate()
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

        self.test_folder = os.path.abspath(test_folder)

    def run_all_tests(self):
        """
        Runs all tests on binaries in the specified folder.
        """
        # Test packed vs non-packed viruses
        detection = self.test_detection()

        # Check correctness for packed vs non-packed binaries
        correctness = self.test_correctness(TEST_BINARY_LIST)

        # Check speed for packed vs non-packed binaries
        speed = self.test_speed(TEST_BINARY_LIST)

    def test_detection(self):
        """
        Runs tests for binaries via VirusTotal, in order to check how much of an effect packing the binary has
        on the detection rates of various scanners.

        :return: A dict containing the results of the tests.
        """
        print("[*] Testing detection rate against VirusTotal")
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

    def test_correctness(self, test_binary_list):
        """
        Tests whether the packed binaries work as expected after being packed.

        :param test_binary_list: A dict containing a list of binaries to run, as well as various flags to run them with
        :return: A dict containing the results of the tests.
        """
        print("[*] Testing execution correctness")
        bin_dir = os.path.join(self.test_folder, 'bin')

        # Clean up any already packed files
        print("[*] Cleaning up previously packed files")
        self._clean_packed_files(bin_dir)

        # Evaluate the functions that are called in general use
        print("[*] Retrieving functions used in general execution to limit encryption effect")
        used_functions = self._run_test_binaries(
            bin_dir, test_binary_list, TestRunner.run_profiler,
            save_opts=False, save_results=True, save_path="all_functions.json")

        # Repack the rest of the files and test each one
        print('[*] Encrypting all binaries')
        for file in used_functions.keys():
            file = os.path.join(bin_dir, file)
            TestRunner._encrypt_binary(file, used_functions)

        print("[*] Checking the output of the original non-encrypted binaries")
        original_results = self._run_test_binaries(
            bin_dir, test_binary_list, lambda x, y: y,
            save_opts=True, save_results=False)

        print("[*] Checking the output of the encrypted binaries")
        # Update the keys to point to packed binaries
        packed_binary_list = self._create_packed_list(test_binary_list)

        packed_results = self._run_test_binaries(
            bin_dir, packed_binary_list, lambda x, y: y,
            save_opts=True, save_results=False)

        # Create the TestResult objects
        output = {}
        for original_key in original_results.keys():
            packed_key = f"{original_key}.packed"
            original = original_results[original_key]
            packed = packed_results[packed_key]
            output[original_key] = CorrectnessTestResult(original_key, original, packed)

        return output

    def test_speed(self, test_binary_list):
        print("[*] Testing execution correctness")
        bin_dir = os.path.join(self.test_folder, 'bin')

        # Clean up any already packed files
        print("[*] Cleaning up previously packed files")
        self._clean_packed_files(bin_dir)

        # Evaluate the functions that are called in general use
        print("[*] Retrieving functions used in general execution to limit encryption effect")
        used_functions = self._run_test_binaries(bin_dir, test_binary_list)

        # Repack the rest of the files and test each one
        print('[*] Packing and testing correctness')
        return self._get_speed_results(bin_dir, test_binary_list, used_functions)

    @staticmethod
    def _get_detection_results(virus_dir):
        """
        Gets the results from running VirusTotal scans on the files in the specified folder.

        :param virus_dir: The folder containing the list of binaries to scan.
        :return: A dict containing the results of the scans
        """
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
    def _run_test_binaries(bin_dir, test_binary_list, post_exec_func, save_opts, save_results=False, save_path=''):
        """
        This function loops through a list of binaries and specific arguments/options for each of those binaries, runs
        them, then executes the post_exec_func function to transform any results.

        :param bin_dir: The folder containing the binaries
        :param test_binary_list: A dict containing binaries and list of arguments to pass each one
        :param post_exec_func: The function to run after initial binary execution, signature fn(bin_path, output)
        :param save_opts: Whether the output should include all binary parameters as keys or not
        :param save_results: True if the results of the output should be serialized to a file or not
        :param save_path: The path to serialize the results to if save_results is set to True
        :return: A dict of binaries and the functions they've run during execution
        """
        return_output = {}

        # Check if the results are saved in a file
        all_functions_path = os.path.join(bin_dir, save_path)
        if save_results is True and os.path.exists(all_functions_path):
            with open(all_functions_path, 'r') as f:
                return json.loads(f.read())

        # The test binary used to modify
        test_file = '../test/source/test'
        dirname = os.path.dirname(__file__)
        test_file = os.path.join(dirname, test_file)

        # Loop through each binary and execute it with the various options supplied
        for execution_string in test_binary_list.keys():
            opts = test_binary_list[execution_string]
            bin_name = execution_string.split(' ')[0]
            bin_key = bin_name.split('/')[1]
            bin_path = os.path.join(bin_dir, bin_key)
            execution_string = os.path.join(bin_dir, execution_string)

            for opt in opts:

                # Copy the test binary new each time
                test_bin = os.path.join(bin_dir, 'test')
                copyfile(test_file, test_bin)

                # Run the program and it's arguments
                run_string = execution_string.format(opt, test_bin)
                print(f"\t[+] {run_string}")
                try:
                    execution_output = check_output(run_string.split(' '))
                except Exception as ex:
                    print(f"\t[+] {run_string} failed: {str(ex)}")
                    execution_output = None

                execution_output = post_exec_func(bin_path, execution_output)

                # Store the functions as a set to remove duplicates
                if bin_key not in return_output:
                    return_output[bin_key] = {} if save_opts else set()

                if save_opts:
                    return_output[bin_key][opt] = execution_output
                else:
                    return_output[bin_key].update(execution_output)

            # Deduplicate results
            if not save_opts:
                return_output[bin_key] = sorted(list(return_output[bin_key]))

        # Save the file to prevent running again
        if save_results is True:
            with open(all_functions_path, "w") as f:
                f.write(json.dumps(return_output))

        return return_output

    @staticmethod
    def run_profiler(bin_path, output):
        """
        This function takes the output from running a binary and extracts the functions that were called during
        execution.

        Each binary must be compiled with the -fp flag so as the profiler gprof can work. A test file is provided during
        each execution as a fresh binary so each output is consistent.

        :param bin_path: The location of the binaries
        :param output: The output from the binary execution
        :return: A list of functions that were run during program execution
        """
        if output is None:
            return None

        # Run the profiler to check which functions have been touched in execution
        ps = Popen(['gprof', '-b', '-p', bin_path], stdout=PIPE)
        awk = Popen(['awk', "{print $7}"], stdin=ps.stdout, stdout=PIPE)
        sed = Popen(["sed", "-r", "/^\s*$/d"], stdin=awk.stdout, stdout=PIPE)
        output = check_output(['grep', '-v', 'name'], stdin=sed.stdout)
        output = output.decode('utf-8').split('\n')

        # Remove the gprof file
        os.remove('gmon.out')

        return output

    @staticmethod
    def _encrypt_binary(file_path, used_functions):
        """
        Encrypts the binary in the path specified, only selecting those functions specified.

        :param file_path: The path of the binary to encrypt
        :param used_functions: The list of functions to select
        """
        # Encrypt the binary using the list of functions provided
        rnd = Random(SEED)
        key = rnd.randint(0, 100)
        packer = ELFPacker(file_path)
        all_functions = packer.list_functions()
        chosen_funcs = []
        for af in all_functions:
            if af.name in used_functions[os.path.basename(file_path)] \
                    and 'bfd' not in af.name:  # TODO: Remove this
                chosen_funcs.append(af)
        print(f"\t[+] Encrypting {len(chosen_funcs)} out of {len(all_functions)}")
        packer.encrypt(key, chosen_funcs)

    @staticmethod
    def _clean_packed_files(folder):
        """
        Removes any file with the ".packed" extension in the folder specified

        :param folder: The folder to clean
        """
        for root, _, files in os.walk(folder):
            for file in files:
                file = os.path.join(root, file)
                if file.endswith('packed'):
                    os.remove(file)

    @staticmethod
    def _create_packed_list(test_binary_list):
        """
        Modifies the list of binaries and arguments in the list, and appends ".packed" to the name of the binary.

        :param test_binary_list: The original list of binaries with arguments
        :return: The same input list with ".packed" appended to the binary name
        """
        packed_binary_list = test_binary_list.copy()
        for key in test_binary_list.keys():
            bin_key = key.split(' ')[0].split('/')[1]
            packed_key = key.replace(bin_key, f"{bin_key}.packed")
            packed_binary_list[packed_key] = packed_binary_list.pop(key)
        return packed_binary_list


def test_script():
    os.chdir('..')
    runner = TestRunner('test')
    runner.test_correctness(TEST_BINARY_LIST)


if __name__ == "__main__":
    test_script()
