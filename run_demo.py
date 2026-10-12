from seed import seed
from engine import list_alerts, stats

if __name__ == "__main__":
    seed()
    print(stats())
    for alert in list_alerts():
        print(f"{alert['alert_uid']} | {alert['severity']} | {alert['rule_id']} | {alert['title']}")
