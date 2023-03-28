import torch
from multiprocessing import Pool
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


def generate_hexdump(file: str, write: bool) -> list[tuple[int, str]]:
    """Generates a hexdump of a pcap file and writes it to a csv file or returns it."""
    print(os.path.getsize(f"original_data/Wednesday-14-02-2018/pcap/{file}") >> 20,
          "MB", flush=True, end="\t")
    print(file, flush=True)
    # infile: list[(timestamp, packet)]
    infile = dpkt.pcap.Reader(open(f"original_data/Wednesday-14-02-2018/pcap/{file}", "rb"))
    infile = [(i[0], i[1].hex()) for i in infile]
    if write:
        with open("transformed_data/14_02.csv", "a") as f:
            writer = csv.writer(f)
            writer.writerows(infile)
            print("<<<",
                  os.path.getsize("transformed_data/14_02.csv") >> 30, "GB",
                  subprocess.run("wc -l transformed_data/14_02.csv", shell=True,
                                 capture_output=True).stdout.split()[0],
                  ">>>")
    else:
        return infile

def read_csv(filename: str) -> list[str]:
    with open(filename, "r") as f:
        lines = f.readlines()
    lines = [i.strip().split(",") for i in lines]
    lines = lines[1:]
    return lines

def transform_line(line: str) -> tuple[int, str]:
    """Transforms a line of a csv file into the desired format."""
    line = (datetime.strptime(line[2], "%d/%m/%Y %H:%M:%S").strftime("%s"), line[-1])
    return line

def get_label_counts(labels):
    unique = {}
    for i in labels:
        if i not in unique:
            unique[i] = 1
        else:
            unique[i] += 1
    return unique
    
    
def main():
    # Get the labels
    # csv = read_csv("processed_data/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv")
    # with Pool(12) as pool: labels = pool.map(transform_line, csv)
    # for i in labels[:10]: print(i)
    # print(len(labels), get_label_counts([i[1] for i in labels]))
    
    # Get the packets
    os.remove("transformed_data/14_02.csv")
    files_14_02 = os.listdir("original_data/Wednesday-14-02-2018/pcap")[:100]
    tasks = [(i, True) for i in files_14_02]
    with Pool(10) as pool: packets = pool.starmap(generate_hexdump, tasks)
        
    # packets = [i for j in packets for i in j]
    # print(len(packets))


if __name__ == "__main__":
    main()
