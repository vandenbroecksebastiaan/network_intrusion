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


class Dataset(torch.utils.data.Dataset):
    def __init__(self, data, labels):
        self.data = data
        self.labels = labels

    def __getitem__(self, index):
        return self.data[index], self.labels[index]

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
                if len(str(file_name)) < 4:
                    print(file_name)
                    break
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
           writer.writerows(read_csv(origin_path+file))
           os.remove(origin_path+file)
           print(os.path.getsize(destination_path) >> 20, "MB | Num. of lines:",
                 subprocess.run(f"wc -l {destination_path}", shell=True,
                                capture_output=True).stdout.split()[0],
                 end="\n")

def read_csv(filename: str) -> list[str]:
    with open(filename, "r") as f:
        lines = f.readlines()
    lines = [i.strip().split(",") for i in lines][1:]
    return lines

def write_target(target):
    with open("transformed_data/14_02/target.csv", "w") as f:
        csv.writer(f).writerows(target)

def generate_target_tuple(line: str) -> tuple[int, str]:
    target = (datetime.strptime(line[2], "%d/%m/%Y %H:%M:%S").strftime("%s"), line[-1])
    return target

def get_label_counts(labels):
    unique = {}
    for i in labels:
        if i not in unique:
            unique[i] = 1
        else:
            unique[i] += 1
    return unique
    
    
def main():
    # Start fresh
    for i in os.listdir("transformed_data/14_02"): os.remove(f"transformed_data/14_02/{i}") 
    # Get the labels
    csv = read_csv("processed_data/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv")
    with Pool(10) as pool: target = pool.map(generate_target_tuple, csv)
    write_target(target)
    del target
    
    # Get the packets
    files_14_02 = os.listdir("original_data/Wednesday-14-02-2018/pcap")
    tasks = [(i, True, idx) for idx, i in enumerate(files_14_02)]
    # Generate csv files from the pcap files
    with ProcessPoolExecutor(8) as executer:
        executer.map(generate_hexdump, [i[0] for i in tasks],
                     [i[1] for i in tasks], [i[2] for i in tasks], chunksize=10)
    transform_hexdump() 
            

        


if __name__ == "__main__":
    main()
