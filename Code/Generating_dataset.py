from Feature_extraction import Feature_extraction
import time
import warnings
warnings.filterwarnings("ignore")

import os
from tqdm import tqdm
from multiprocessing import Process
import numpy as np
import pandas as pd

if __name__ == "__main__":

    start = time.time()
    print("\n========== CIC IoT feature extraction ==========")

    # Handle command line arguments if provided
    import sys
    
    pcapfilesdir = "pcap_files"
    pcap_file_path = None
    csv_output_path = None
    
    if len(sys.argv) > 1:
        # Single file mode - process specific pcap file
        pcap_file_path = sys.argv[1]
        if len(sys.argv) > 2:
            csv_output_path = sys.argv[2]
        pcapfiles = [os.path.basename(pcap_file_path)]
        pcapfilesdir = os.path.dirname(pcap_file_path)
        if not pcapfilesdir:
            pcapfilesdir = "."
    else:
        # Original directory scan mode
        pcapfiles = os.listdir(pcapfilesdir)
    
    subfiles_size = 10  # MB
    split_directory = "split_temp/"
    destination_directory = "output/"
    converted_csv_files_directory = "csv_files/"
    n_threads = 8
    
    # Ensure directories exist with proper permissions
    os.makedirs(split_directory, exist_ok=True)
    os.makedirs(destination_directory, exist_ok=True)
    os.makedirs(converted_csv_files_directory, exist_ok=True)
    
    # Ensure the directories are writable
    os.system(f"chmod 777 {split_directory} {destination_directory}")
    
    address = "./"

    for i in range(len(pcapfiles)):
        lstart = time.time()
        pcap_file = pcapfiles[i]
        print(pcap_file)
        print(">>>> 1. splitting the .pcap file.")
        os.system(
            "tcpdump -r "
            + os.path.join(pcapfilesdir, pcap_file)
            + " -w "
            + split_directory
            + "split_temp -C "
            + str(subfiles_size)
        )
        subfiles = os.listdir(split_directory)
        print(">>>> 2. Converting (sub) .pcap files to .csv files.")
        processes = []
        errors = 0

        subfiles_threadlist = np.array_split(subfiles, (len(subfiles) / n_threads) + 1)
        for f_list in tqdm(subfiles_threadlist):
            n_processes = min(len(f_list), n_threads)
            assert n_threads >= n_processes
            assert n_threads >= len(f_list)
            processes = []
            for i in range(n_processes):
                fe = Feature_extraction()
                f = f_list[i]
                subpcap_file = split_directory + f
                p = Process(
                    target=fe.pcap_evaluation,
                    args=(subpcap_file, destination_directory + f.split(".")[0]),
                )
                p.start()
                processes.append(p)
            for p in processes:
                p.join()
        assert len(subfiles) == len(os.listdir(destination_directory))
        print(">>>> 3. Removing (sub) .pcap files.")
        for sf in subfiles:
            os.remove(split_directory + sf)

        print(">>>> 4. Merging (sub) .csv files (summary).")

        csv_subfiles = os.listdir(destination_directory)
        mode = "w"        
        for f in tqdm(csv_subfiles):
            try:
                d = pd.read_csv(destination_directory + f)
                output_csv_path = os.path.join(converted_csv_files_directory, pcap_file[:-5] + ".csv")
                
                # If a specific CSV output path was provided, use that instead
                if csv_output_path and i == 0:  # Only for first pcap in case of multiple
                    output_csv_path = csv_output_path
                    
                d.to_csv(
                    output_csv_path,
                    header=mode == "w",
                    index=False,
                    mode=mode,
                )
                mode = "a"
            except Exception as e:
                print(f"Error processing CSV file: {e}")
                errors += 1

        print(">>>> 5. Removing (sub) .csv files.")
        for cf in tqdm(csv_subfiles):
            try:
                os.remove(destination_directory + cf)
            except Exception as e:
                print(f"Error removing file: {e}")
                
        print(
            f"done! ({pcap_file})("
            + str(round(time.time() - lstart, 2))
            + "s),  total_errors= "
            + str(errors)
        )

        end = time.time()
        print(f"Elapsed Time = {(end-start)}s\n")
