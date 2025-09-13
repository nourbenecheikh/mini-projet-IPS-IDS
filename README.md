## 1. Présentation du projet
**Objectif :** Développer un système léger de détection et prévention d’intrusions (IDS/IPS) capable de :  
- Détecter les scans de ports SYN  
- Détecter les attaques ICMP flood  
- Bloquer automatiquement les IP suspectes via `iptables`  
- Générer des logs pour les alertes et les actions  

**Technologies utilisées :**  
- Python 3  
- Bibliothèque `scapy`  
- `iptables` pour le blocage réseau  
- Ubuntu / Termux pour tests
# 2. Fonctionnement

1. **Sniffing des paquets**  
   - Le script écoute tous les paquets sur les interfaces réseau.  
   - Analyse TCP pour détecter les scans SYN.  
   - Analyse ICMP pour détecter les floods.

2. **Détection**  
   - Port scan : si un même IP essaie `PORT_SCAN_THRESHOLD` ports différents dans `PORT_SCAN_WINDOW` secondes → alerte.  
   - ICMP flood : si un même IP envoie `ICMP_THRESHOLD` paquets ICMP dans `ICMP_WINDOW` secondes → alerte.  

3. **Prévention**  
   - IP suspecte **bloquée temporairement** via `iptables` pour `BLOCK_DURATION` secondes.  
   - Les IP de la whitelist ne sont jamais bloquées.  

4. **Logs**  
   - `alerts.log` : contient toutes les alertes détectées.  
   - `blocked.log` : contient les actions de blocage et déblocage des IP.  

