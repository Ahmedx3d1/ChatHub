# 🔐 ChatHub (CLI Secure Chat)

> A lightweight, secure command-line chat application built in Python using sockets and hybrid encryption (AES + RSA), designed for Linux users.

---

## 📌 Overview

**ChatHub** is a terminal-based real-time chat application that focuses on **secure communication** over networks. It leverages **hybrid encryption**, combining the strengths of RSA and AES to ensure both **secure key exchange** and **fast message transmission**.

This project is ideal for learning and experimenting with:

* Network programming using sockets
* Cryptography fundamentals
* Secure communication protocols

---

## ✨ Features

* 🔗 **Client-Server Architecture**
  Built using Python sockets for real-time communication.

* 🔐 **Hybrid Encryption (AES + RSA)**

  * RSA for secure key exchange
  * AES for fast, symmetric message encryption

* 💬 **Real-Time Messaging**
  Send and receive encrypted messages instantly.

* 🐧 **Linux-Focused**
  Designed and tested for Linux environments.

* ⚡ **Lightweight CLI Interface**
  Minimal and fast terminal-based interaction.

---

## 🔐 How It Works

1. **Connection Establishment**

   * Client connects to the server via TCP sockets.

2. **RSA Key Exchange**

   * RSA is used to securely exchange a symmetric AES key.

3. **AES Encryption**

   * All messages are encrypted using AES before transmission.

4. **Secure Communication**

   * Messages are decrypted on the receiving end using the shared AES key.

---

## 🛠️ Tech Stack

* **Language:** Python 3
* **Networking:** `socket`
* **Encryption:**

  * RSA (asymmetric encryption)
  * AES (symmetric encryption)

---

## ⚙️ Installation

### 🔹 Requirements

* Python 3.x
* Linux OS

### 🔹 Clone the Repository

```bash
git clone https://github.com/Ahmedx3d1/ChatHub.git
cd ChatHub
```

### 🔹 Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### 1️⃣ Start the Server

```bash
python server.py
```

### 2️⃣ Start the Client

```bash
python client.py
```

> Run multiple clients in separate terminals to simulate chat.

---


## 🧠 Use Cases

* Learning socket programming in Python
* Understanding hybrid encryption systems
* Building secure communication tools
* Educational demonstrations of RSA & AES

---

## ⚠️ Disclaimer

This project is intended for **educational purposes only**.
While it demonstrates secure communication concepts, it is **not production-ready** and should not be used for sensitive data in real-world applications without further security enhancements.



> Built with 🔐 security and simplicity in mind.
