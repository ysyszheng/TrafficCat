import torch
import torch.nn as nn
import torch.nn.functional as F
import preprocess

# Neural Network
class NN(nn.Module):
    # Constructor
    def __init__(self):
        super().__init__()
        self.dense1 = nn.Linear(28, 64)
        self.dense2 = nn.Linear(64, 64)
        self.dense3 = nn.Linear(64, 32)
        self.dense4 = nn.Linear(32, 16)
        self.dense5 = nn.Linear(16, 23)

    # Forward pass
    def forward(self, X):
        # X = F.relu(self.dense1(X))
        X = F.elu(self.dense1(X))
        X = F.dropout(X, p=0.33)

        # X = F.relu(self.dense2(X))
        X = F.elu(self.dense2(X))
        X = F.dropout(X, p=0.33)

        # X = F.relu(self.dense3(X))
        X = F.elu(self.dense3(X))
        X = F.dropout(X, p=0.33)

        # X = F.relu(self.dense4(X))
        X = F.elu(self.dense4(X))
        X = F.dropout(X, p=0.33)

        X = self.dense5(X)

        return X


if __name__ == "__main__":
    # Load model
    model = NN()
    model.load_state_dict(torch.load("kdd/inference/model/faashark.pt"))

    # Load data
    data = preprocess.read_data("data/extractor.txt")
    data = torch.tensor(data, dtype=torch.float)

    # Inference
    model.eval()
    with torch.no_grad():
        outputs = model(data)
        _, predicted = torch.max(outputs, 1)

    # Save labels
    labels = [
        "normal",
        "buffer_overflow",
        "loadmodule",
        "perl",
        "neptune",
        "smurf",
        "guess_passwd",
        "pod",
        "teardrop",
        "portsweep",
        "ipsweep",
        "land",
        "ftp_write",
        "back",
        "imap",
        "satan",
        "phf",
        "nmap",
        "multihop",
        "warezmaster",
        "warezclient",
        "spy",
        "rootkit",
    ]
    # predicted_labels = [labels[i] for i in predicted.numpy()]
    predicted_labels = [labels[i] for i in predicted]

    # Save labels
    with open("data/label.txt", "w") as f:
        for label in predicted_labels:
            f.write(label + "\n")
