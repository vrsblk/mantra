# mantra

mantra.py - a pure-Python (standard library only) port of mantra.
 
Hunts for leaked API keys / secrets in JavaScript files and HTML pages.
Reads URLs from stdin, one per line:
 
    cat js.txt | python3 mantra.py
    cat js.txt | python3 mantra.py -t 100 -d -ep 'my_custom_[a-z]{10}'
 
Only use it on targets you own or are authorised to test.
