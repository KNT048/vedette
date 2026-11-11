# Stands in for hpfeeds (GPL-3), which OpenCanary imports at the top of logger.py but calls only for an hpfeeds logger (D-162).
def new(*a, **k):
    raise RuntimeError("hpfeeds is not shipped (D-162)")
