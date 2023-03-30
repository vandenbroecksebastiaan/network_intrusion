import torch
from multiprocessing import Pool
from concurrent.futures import ProcessPoolExecutor
import os
import time
from datetime import datetime
from tqdm import tqdm
import os
import dpkt
import csv
import subprocess


class PacketDataset(torch.utils.data.Dataset):
    def __init__(self):
        self.data_files = os.listdir("transformed_data/14_02")
        self.data_files = [i[:-4] for i in self.data_files]
        print("Number of files before removing:", len(self.data_files))
        self.data_files = [int(i) for i in self.data_files if len(i) > 9]
        print("Number of files after removing:", len(self.data_files))
        
        self.target = read_csv("transformed_data/14_02/target.csv")
        self.target = [[int(i[0]), float(i[1])] for i in self.target]
        
        print("len target:", len(self.target))
        print("len data_files:", len(self.data_files))
        
        for i in zip(self.data_files[1000:1100], self.target[1000:1100]): print(i)
        
        target_timestamps = [i[0] for i in self.target]
        file_timestamps = [int(i) for i in self.data_files]
        
        print("number of files with a target")
        is_in = [i for i in file_timestamps if i in target_timestamps]
        print(len(is_in))
        
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

def transform_hexdump():
    file_list = [i for i in os.listdir("transformed_data/14_02")]
    file_list = [i for i  in file_list if (i[:3] == "cap") or (i[:4] == "UCAP")]
    for i in tqdm(file_list):
        with open(f"transformed_data/14_02/{i}", "r") as file:
            packets = [i.split(",") for i in file.readlines()]
            for obs in packets:
                file_name = int(float(obs[0]))
                payload = obs[1]
                with open(f"transformed_data/14_02/{file_name}.csv", "a") as f:
                    f.write(payload)
            os.remove(f"transformed_data/14_02/{i}")
    
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
    with Pool(10) as pool: target = pool.map(generate_target_tuple, csv)
    print("shape before:", len(target))
    target = [i for i in target if i[0] > 1.5e9]
    print("shape after:", len(target))
    target = transform_target(target)
    write_target(target); del target;
    
    # Get the packets
    files_14_02 = os.listdir("original_data/Wednesday-14-02-2018/pcap")
    tasks = [(i, True, idx) for idx, i in enumerate(files_14_02)]
    # Generate csv files from the pcap files
    with ProcessPoolExecutor(7) as executer:
        executer.map(generate_hexdump, [i[0] for i in tasks],
                     [i[1] for i in tasks], [i[2] for i in tasks], chunksize=10)
    transform_hexdump() 
    """
    from scapy.utils import RawPcapReader, tcpdump
    pcaps = RawPcapReader("original_data/Wednesday-14-02-2018/pcap/capDESKTOP-AN3U28N-172.31.64.26")
    print(pcaps.next())
    # print(tcpdump("original_data/Wednesday-14-02-2018/pcap/capDESKTOP-AN3U28N-172.31.64.26"))
    """

    

if __name__ == "__main__":
    main()
