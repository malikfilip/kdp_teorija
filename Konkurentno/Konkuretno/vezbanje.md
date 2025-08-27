vezbanje

## tiebreaker

```cpp
int in[n]; //gde sam ja stigao
int last[n] = {0}; //n faza cekanja

process CSi{
    while(true){
        for(int j = 0; j < n; j++)//prolazim kroz N faza cekanja
            in[i] = j; //Ja sam stigao u j-ti korak
            last[j] = i; //U j-tom koraku sam ja poslednji
            for(int k = 0; k<n && k!=i){
                while(in[i] <= in[k] && last[j] == i) skip;
            }
            //Critical section
            in[i] = 0;
            //non critical section
    }

    
}

```

## ticket algoritam

```cpp
int number = 0;
int next = 0;
int turn[n] = {0};

process CSi{
    while(true){
        turn[i] = FA(number,1);
        while(turn[i]!=next) skip;
        //CS
        next = next +1;
        turn[i]=0;//opciono
        //NON-CS
        
    }
    
}

```

## bakery algoritam

```cpp
turn[n] = {0};//ako je turn = 0 necu da udjem u CS
//maks instrucija
process CSi{
    while(true){
        <turn[i]=MAX(turn);>
        for(int j = 0, j<n && j!=i;j++){
            await(turn[i] < turn[j] || turn[j] = 0)
                //whlie(turn[i] >= turn[j] && turn[j] !=0) skip
        }
        //CS
        turn[i] = 0;
        //NONCS
        
        
    }
    
}
//Coarse grain
process CSi{
    while(true){
        turn[i] = 1; //apsolutno ne kapiram ovo
        turn[i]=MAX(turn);
        for(int j = 0, j<n && j!=i;j++){
            
                whlie((turn[i],i) > turn(turn[j],j) && turn[j] !=0) skip
        }
        //CS
        turn[i] = 0;
        //NONCS
        
        
    }
    
}

```

## andersenov algoritam

```cpp
int slot = 0;
bool flags[n] = {false};
flags[1] = true;

process CSi{
    while(true){
        <mySlot = (slot + 1) % N; slot = slot + 1;>
        <await(flags[mySlot])>
            //CS
        flags[mySlot] = false;
        flags[mySlot + 1] = true;
        //NonCs
    }


}

```

```cpp
int slot = 0;
bool flags[n] = {false};
flags[1] = true;

while(true){
    mySlot = FA(slot,1) % n + 1;
    while(!flags[mySlot]) skip;
    //CS
        flags[mySlot] = false;
        flags[mySlot % N + 1] = true;
    //NONCS

    
}


```

## CLH

```cpp
Node tail = Node(false);
process CSi{
    while(true){
        Node prev = Node();
        Node node = Node(true);
        <prev = tail; tail = node;> //prevezivanje
        await(!prev.locked());
        //CS
        <node.locked = false;>
        //NON CS
    }
}
```

```cpp
Node tail = Node(false);
process CSi{
    while(true){
        Node prev = Node();
        Node node = Node(true);

        GS(tail,node);

        while(prev.locked())skip;
        //CS
        node.locked = false;
        //NON CS
    }
} //GS (get & set)-getuje staru vrednost i setuje novu
```

## barijere

```cpp
int arrive[n];
int continue[n];
process CSi{
    //Posao
    <arrive[i] = 1;>
    <await continue[i] == 1>
        //cs
    continue[i]=0;
    //noncs
    
    
}
process Coordinator{

    for (proc in Process){
        <await(arrive[proc.i])>;
            arrive[proc.i] = 0;
    }
    
    for (proc in Process){
        <continue[proc.i] = true>;
    }
    
    
}

```

## producers consumers bounded buffer problem

```cpp
//1 producer & 1 consumer

item buf; //Neki ajtem, ili null
Sem sem1 = 0;
Sem sem2 = 1;
process Consumer{
    while(true){
        item storage;
        wait(sem1);
        storage = buf;
        signal(sem2);
        
    }
}

process Producer{
    while(true){
        item new = produceItem();
        wait(sem2);
        buf = item;
        signal(sem1);
    }
    
}

```

```cpp
item buf[n];
int front = 0, rear = 0;
Semaphore full = 0;
Semaphore empty = N
Semaphore mutexC = 1; mutexP = 1;
Process Producerm{
    while(true){
        wait(empty);
        wait(mutexP);
        buf[rear] = getItem();
        rear = rear + 1 % N;
        signal(mutexP);
        signal(full);
    }
    
}

process Consumeri{
    while(true){
        wait(full);
        wait(mutexC);
        item = buf[front];
        front = front + 1 % N;
        signal(mutexc);
        signal(empty);
    }

    
}

```

## dining philosopherzi

```cpp
Sem forks[N] = 1;
process Philosopher0..n-2{

    while(true){
        wait(fork[i]);
        wait(fork[i+1 % N]);
        //has
        signal(fork[i+1 % N]);
        signal(fork[i]);
    }
}



```

## readers writers

coarse grain

```cpp
int readers = 0;
int writers = 0;
process Reader[i = 1 to m]{
    while(true){
        < await (writers == 0) readers = readers + 1;> //Citanje samo kad se ne pise
        ...
            #READ
        ...
        <readers = readers - 1;>
    }
}
process Writer[i = 1 to t]{
    while(true){
        < await (writers == 0 and readers == 0) writers = writers + 1;>//Upis samo ako niko drugi ne upisuje i niko ne cita podatak
        ...
            #WRITE
        ...
        <writers = writers - 1;>
    }
}


```

```cpp
    int readers = 0;
    int writers = 0;
    process Reader[i = 1 to m]{
        while(true){
            //< await (writers == 0) readers = readers + 1;> //Citanje samo kad se ne pise
            wait(e);
            if(writers > 0) {
                dp1++;
                signal(e);
                wait(rs1);
            }
            readers ++;
            SIGNAL;
            ...
                #READ
            ...
            //<readers = readers - 1;>
            wait(e);
            readers--;
            SIGNAL;
        }
}
    process Writer[]{
        while(true){

            wait(e);
            if(cntW > 0 || cntR > 0){
                dp2++;
                signal(e);
                wait(rs2);
            }
            SIGNAL;
            #Write
            wait(e);
            writers--;
            SIGNAL;
        }


        
    }
SIGNAL:

if(writers == 0 && dr1>0) dr1--; signal(rs1);
else if(writers == 0 && readers == 0 && dr2>0) dr2--;signal(rs2);
else signal(e);
```

## readers writers+ stafeta+lista+privatni semafori

&nbsp;

```cpp
Semaphore e = 1;
List lista;
Semaphore rSems[n] = {0}

process Readersi{
    while(true){
        wait(e);
        if(cntW > 0;){
            Lista.put('R',i);
            signal(e);
            wait(rSems[i]);
        }
        cntR++;
        SIGNAL;
        //Read
        wait(e);
        cntR--;
        SIGNAL;
        
    }
    
}

process Consumenrsm{
    while(true){
        wait(e);
        if(cntW > 0 || cntR > 0;){
            Lista.put('W',m);
            signal(e);
            wait(wSems[m]);
        }
        cntW++;
        SIGNAL;
        //Read
        wait(e);
        cntW--;
        SIGNAL;
        
    }
    
}
if(writers == 0 && (List.size()>0 && List.peek(0) == 'R')) signal(List.remove(0));
else if(writers == 0 && readers == 0 && (List.size()>0 && List.peek(0) == 'W')) signal(List.remove(0));
else signal(e);
```
## monitor

Monitori preko samfora:

```cpp

typedef urgentQue{
	sem UQ_sem;
	int count;
}
typedef CV{
	sem CV_sem;
	int count;

	wait(){
		count++;
		if(uq.count > 0){signal(UQ_sem);}
		else(signal(e));
		wait(CV_sem);
		count--;
	}
	signal(){
		if(count>0){ 
			UQ_count++;
			signal(CV_sem);
			wait(UQ_sem);
			UQ_count--;
			 }
		
	}
}

class Monitor{
	CV condVar;
	public void procedure(){
		wait (e);
		
		#Posao
		if(uq.count > 0) signal(uq);
			else signal (e)
		
	}

	
}
```
## BOUNDER BUFFER

```cpp

Monitor BB{
	Cond cv1,cv2;
	item buff[n];
	int rear,front,count = 0;
	
	procedure Consume(){
		if(count == 0) c2.wait();
		buf[front] = item;
		front = front++ % N;
		count--;
		c1.signal();
	};
	procedure Produce(){
		if(count == N) c1.wait();
		item = buff[rear];
		rear = rear++ % N;
		count++;
		c2.signal();
	};
}


```

## readers writers i signallAll

```cpp


Monitor sleeping{
	int chair = 0;
	int barber = 0;
	int open = 0;

	Cond b;
	Cond c;
	Cond o;
	Cond l;

	procedure get_nexT(){
		barber++;
		b.signal();
		while(char==0)c.wait();
		chair--;
		
	}
	procedure get_cut(){
		while(b==0)b.wait();
		barber--;
		chair++;
		c.signal();
		while(open==0)o.wait();
		open--;
		l.signal();
		
	}
	procedure leave(){
		open++;
		o.signal();
		while(open>0)l.wait();
		
	}

	
}
```

```cpp
class Canyon(){
	int k =0;
	int i =0;
	
}
Canyon c = new Canyon();
void kauboj(){
	region(c){
		
		await(i == 0);
		k++;
	}
	//prodji kanjoj
	region(c){
		
		k--;
	}
	
}



```

```cpp

Monitor gajbaca{ 
	int ivica = 0;
	int ticket=0, next=0;
	Cond beraci
	Cond traktori;
	procedure ostavljam_gajbizze(int gajbe){
		ivica+= gajbe;
		if(ivica>prikolica_kapacitet && traktori.queue>0)traktori.signal();
	}
	procedure spreman_da_pokupim(int prikolica){
		int myTicket = ticket++;
		if(prikolica_kapacitet > ivica || myTicket !=next;)traktori.wait(myTicket);
		ivica-=prikolica;
		next++;
	}
}

```
```cpp
Sem b1 = 1;
Sem b2 = 0;
int cnt;

process CS{
	wait(b1);
	
	cnt++
	if(cnt == N)signal(b2);
		else signal(b1);
	//prolazimo
	cnt--;
	if(cnt == 0)signal(b1);
	else signal(b2);
	
}

process CS{ <await(cnt == N)>
	wait(b1);
	cnt++;
	if(cnt != N){
		signal(b1);
		wait(b2);
	}
	cnt--;
	if(cnt>0){signal(b2);}
		else(signal(b1);)
	
}

```
```cpp

1P i 1C
item buf[N];
int front = 0, rear=0;
process Producer{
	wait(semP);
	buf[rear]=item;
	rear = rear + 1 % N
	signal(semC);
}
process Consumer{
	wait(semC);
	item = buf[front];
	front = front + 1 % N;
	signal(semP);
}


```
```cpp

MP i NC
item buf[N];
int front = 0, rear=0;
process Producer{
	wait(semP);
	wait(mutexP);
	buf[rear]=item;
	rear = rear + 1 % N;
	signal(mutexP);
	signal(semC);
}
process Consumer{
	wait(semC);
	wait(mutexC);
	item = buf[front];
	front = front + 1 % N;
	signal(mutexC);
	signal(semP);
}


```

## tiketcina

```cpp
int ticket = 0;
int next = 1;

process{//addAndGet(var, incr) : < var = var + incr; return(var); >

	while(true){
			AG(ticket,1);
		while(myTicket != next)skip;
			//CS
			next++;
			//NONCS
	}
}
```


```cpp
anderzenov alg
bool flags[n] = {false;}
flags[1] = true;
int num = 1;
process CS{
	while(true){
		<int myNum = num; num = num % N +1;>
		<await (flags[myNum] == true)>
		//cs
		<flags[myNum] = false;
		flags[myNum + 1 % N] = true;>
		//noncs

		
	}
}
```
```cpp
anderzenov alg
bool flags[n] = {false;}
flags[1] = true;
int num = 1;
process CS{
	while(true){
		<int myNum = num; num = num % N +1;>
		<await (flags[myNum] == true)>
		//cs
		<flags[myNum] = false;
		flags[myNum + 1 % N] = true;>
		//noncs

		
	}
}
```

umesto FA SWAP
SWAP(var1, var2) : < temp = var1; var1 = var2; var2 = temp; >

```cpp
anderzenov alg
bool flags[n] = {false;}
flags[1] = true;
int num = 1;
int global_lock = 1;
process CS{
	while(true){
		int lock = 0;
		while(lock == 0) SWAP(lock,old_lock);
		//svaki novi proces koji dodje ce dobiti lock = 0;
		//global_lock = 1;
		global_lock = 1;
		int myNum = num; num = num % N +1;
		while (flags[myNum] == false) skip;
		//cs
		flags[myNum] = false;
		flags[myNum + 1 % N] = true;
		
		//noncs

		
	}
}
```

## clh

```cpp

Node head = Node(false);
process{
	while(true){
		Node node = new Node()
	}
}

```