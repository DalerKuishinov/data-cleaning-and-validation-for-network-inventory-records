# LLM Prompt and Response - Call #1

## Model Information
- Model: llama-3.3-70b-versatile
- Temperature: 0.1
- Max Tokens: 2000

---

## Prompt

```
You are a network inventory data classifier. Classify each device into one of these categories:
- server
- workstation
- printer
- switch
- router
- iot
- unknown

For each device, provide:
1. device_type: one of the categories above
2. confidence: "high", "medium", or "low"
3. reasoning: brief explanation (1 sentence)

Input records:
[
  {
    "id": 0,
    "hostname": "host-02",
    "device_type_raw": "",
    "notes": "edge gw?",
    "ip": "10.0.1.300"
  },
  {
    "id": 1,
    "hostname": "local-test",
    "device_type_raw": "",
    "notes": "",
    "ip": "127.0.0.1"
  },
  {
    "id": 2,
    "hostname": "host-apipa",
    "device_type_raw": "",
    "notes": "",
    "ip": "169.254.10.20"
  },
  {
    "id": 3,
    "hostname": "badhost",
    "device_type_raw": "",
    "notes": "",
    "ip": "abc.def.ghi.jkl"
  },
  {
    "id": 4,
    "hostname": "neg",
    "device_type_raw": "",
    "notes": "",
    "ip": "192.168.1.-1"
  },
  {
    "id": 5,
    "hostname": "bcast",
    "device_type_raw": "",
    "notes": "Potential broadcast",
    "ip": "192.168.1.255"
  },
  {
    "id": 6,
    "hostname": "netid",
    "device_type_raw": "",
    "notes": "Potential network id",
    "ip": "192.168.1.0"
  },
  {
    "id": 7,
    "hostname": "missing-ip",
    "device_type_raw": "",
    "notes": "",
    "ip": ""
  }
]

Return ONLY a JSON array with this structure:
[
  {"id": 0, "device_type": "server", "confidence": "high", "reasoning": "hostname pattern srv- indicates server"},
  ...
]

Rules:
- Use hostname patterns (srv-, host-, gw-, sw-, etc.)
- Consider device_type_raw if present but verify it makes sense
- Check notes for clues
- IP type can help (servers often have static IPs)
- Be conservative: use "unknown" if uncertain
```

---

## Response

```
```json
[
  {"id": 0, "device_type": "router", "confidence": "medium", "reasoning": "notes mention edge gw which could indicate a router"},
  {"id": 1, "device_type": "workstation", "confidence": "high", "reasoning": "localhost ip 127.0.0.1 typically indicates a workstation"},
  {"id": 2, "device_type": "workstation", "confidence": "medium", "reasoning": "apiPA ip address often assigned to workstations"},
  {"id": 3, "device_type": "unknown", "confidence": "low", "reasoning": "invalid ip address makes it impossible to determine device type"},
  {"id": 4, "device_type": "unknown", "confidence": "low", "reasoning": "invalid ip address makes it impossible to determine device type"},
  {"id": 5, "device_type": "unknown", "confidence": "low", "reasoning": "broadcast ip address does not indicate a specific device type"},
  {"id": 6, "device_type": "unknown", "confidence": "low", "reasoning": "network id ip address does not indicate a specific device type"},
  {"id": 7, "device_type": "unknown", "confidence": "low", "reasoning": "missing ip address makes it impossible to determine device type"}
]
```
```

---

## Metadata
- Call Number: 1
- Filename: TEMPLATES/prompts.md
