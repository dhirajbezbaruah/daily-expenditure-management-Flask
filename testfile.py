n=44
rev=0
while(n>0):
    dig=n%10
    rev=rev*10+dig
    n=n//10
if n==rev:
    print("Reverse of the number:",rev)