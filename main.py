from torch.utils.data import DataLoader
from data import PacketDataset


def main():
    dataset = PacketDataset()
    dataloader = DataLoader(dataset, batch_size=1, shuffle=False)
    for i in enumerate(dataloader): print(i)


if __name__ == "__main__":
    main()