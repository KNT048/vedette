# An toàn agent

- Mọi Bash có timeout: lệnh nhanh 15 s; test có đích 2 phút; full suite 10 phút; build 5 phút; mạng 30 s.
- Subagent: không full suite, không SSH, không deploy, không quét mạng thật; timeout → báo, không chạy lại.
- Không quét/probe IP ngoài lab của dự án khi phát triển; fixture pcap/XML thay cho mạng thật.
