import torch
from multiprocessing import Pool
from concurrent.futures import ProcessPoolExecutor
import os
from datetime import datetime
from tqdm import tqdm
import os
import dpkt
import csv
import subprocess


class PacketDataset(torch.utils.data.Dataset):
    def __init__(self):
        # Read the target and find all the timestamps for which we have data
        target = read_csv("transformed_data/14_02/target.csv", header=False)
        
        self.data = None
        self.labels = None

    def __getitem__(self, idx):
        return self.data[idx], self.labels[idx]

    def __len__(self):
        return len(self.data)


def generate_hexdump(file: str, write: bool, idx: int):
    print(idx, os.path.getsize(f"original_data/Wednesday-14-02-2018/pcap/{file}") >> 20,
          "MB", file, flush=True, end="\r")
    infile = dpkt.pcap.Reader(open(f"original_data/Wednesday-14-02-2018/pcap/{file}", "rb"))
    infile = [(i[0], i[1].hex()) for i in infile]
    if write:
        with open(f"transformed_data/14_02/{file}.csv", "w") as f:
            csv.writer(f).writerows(infile)
    return infile

def transform_write_hexdump() -> None:
    file_list = [i for i in os.listdir("transformed_data/14_02")]
    file_list = [i for i  in file_list if (i[:3] == "cap") or (i[:4] == "UCAP")]
    bound_exceeded_counter = 0
    for file_name in tqdm(file_list):
        with open(f"transformed_data/14_02/{file_name}", "r") as file:
            packets = [i.split(",") for i in file.readlines()]
            for obs in tqdm(packets, leave=False):
                timestamp = int(float(obs[0]))
                # Subtract 12 hours from the timestamp such that the timestamps
                # from the packets are aligned with the timestamps from target.csv
                timestamp = timestamp - 12*60*60

                upper_bound = datetime(2018, 2, 14, 23, 59, 59).timestamp()
                lower_bound = datetime(2018, 2, 14, 0, 0, 0).timestamp()
                
                if timestamp > upper_bound:
                    bound_exceeded_counter += 1
                    print(" upper bound exceeded:", bound_exceeded_counter, file_name)

                if timestamp < lower_bound:
                    bound_exceeded_counter += 1
                    print(" lower bound exceeded:", bound_exceeded_counter, file_name)

                if (timestamp > lower_bound) and (timestamp < upper_bound):
                    payload = obs[1]
                    # TODO: reduce data leakage from the payload
                    with open(f"transformed_data/14_02/{timestamp}.csv", "a") as f:
                        f.write(payload)

            os.remove(f"transformed_data/14_02/{file_name}")
    
def combine_csv(origin_path: str, destination_path: str) -> None:
    try: os.remove(destination_path)
    except FileNotFoundError: pass

    file_list = os.listdir(origin_path)
    with open(destination_path, "a") as f:
       writer = csv.writer(f)
       for file in tqdm(file_list):
           writer.writerows(read_csv(origin_path+file), header=False)
           os.remove(origin_path+file)
           print(os.path.getsize(destination_path) >> 20, "MB | Num. of lines:",
                 subprocess.run(f"wc -l {destination_path}", shell=True,
                                capture_output=True).stdout.split()[0],
                 end="\n")

def read_csv(filename: str, header=True) -> list[str]:
    with open(filename, "r") as f:
        lines = f.readlines()
    lines = [i.strip().split(",") for i in lines]
    if header: lines = lines[1:]
    return lines

def sort_target(target): target.sort(key=lambda x: x[0])

def transform_target(target: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Calculates the fraction of fraudulant packets in a given second."""
    target_counts = {} # {timestamp: (n_fraudulant, n_total)}
    for i in target:
        if i[0] not in target_counts:
            if i[1] == "Benign":
                target_counts[i[0]] = (0, 1)
            else:
                target_counts[i[0]] = (1, 1)
        else:
            if i[1] == "Benign":
                target_counts[i[0]] = (target_counts[i[0]][0], target_counts[i[0]][1]+1)
            else:
                target_counts[i[0]] = (target_counts[i[0]][0]+1, target_counts[i[0]][1]+1)
                
    return [[int(i[0]), i[1][0]/i[1][1]] for i in target_counts.items()]

def write_target(target: list[tuple[int, str]]) -> None:
    with open("transformed_data/14_02/target.csv", "w") as f:
        csv.writer(f).writerows(target)

def generate_target_tuple(line: list[str]) -> tuple[int, str]:
    target = (datetime.strptime(line[2], "%d/%m/%Y %H:%M:%S").timestamp(), line[-1])
    return target
    
    
def main():
    # Start fresh
    for i in os.listdir("transformed_data/14_02"): os.remove(f"transformed_data/14_02/{i}") 
    # Get the labels
    csv = read_csv("processed_data/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv")
    print(">>> csv in")
    with Pool(10) as pool: target = pool.map(generate_target_tuple, csv)
    print(">>> target generated")
    target = transform_target(target)
    print(">>> target transformed")
    write_target(target); del target;
    print(">>> target written")
    
    # Get the packets
    files_14_02 = os.listdir("original_data/Wednesday-14-02-2018/pcap")
    tasks = [(i, True, idx) for idx, i in enumerate(files_14_02)]
    # Generate csv files from the pcap files
    with ProcessPoolExecutor(7) as executer:
        executer.map(generate_hexdump, [i[0] for i in tasks],
                     [i[1] for i in tasks], [i[2] for i in tasks], chunksize=1)
    print(">>> hexdump generated")
    transform_write_hexdump() 
    print(">>> hexdump transformed and written")
    """
    from scapy.utils import RawPcapReader, tcpdump, PcapReader
    pcaps = PcapReader("original_data/Wednesday-14-02-2018/pcap/capDESKTOP-AN3U28N-172.31.64.26")
    packet = pcaps.next()
    print(tcpdump("original_data/Wednesday-14-02-2018/pcap/capDESKTOP-AN3U28N-172.31.64.26"))
    """

    

if __name__ == "__main__":
    main()
