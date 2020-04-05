## Security Analysis Writeup

From first principles...

### Basic Construction

Subspace is a blockchain protocol
We replace the proof-of-work puzzle with a proof-of-storage audit 
To add a new block you must demonstrate that you possess an old block
With the caveat that each node will store a unique replica of the block
For each audit, if they have the block, they evaluate the replica using the challenge
Any replica that meets the quality threshold may be used to create a new block 
The quality threshold is self-adjusting, such that on average there is one valid solution

### Probabilistic Solutions

In proof-of-work, given enough time there will be a solution
In proof-of-storage, each challenge is evaluated by the network in constant time
Given that the quality threshold is set to obtain 1 valid solution (on average)
For any given challenge

* 1/3 of the time there is exactly one valid solution
* 1/3 of the time there is more than one valid solution 
* 1/3 of the time there is no solution 

[Figure-1] Pyramid solution stack may be the best way to illustrate this

In the cases of one valid solution existing, there is no guarantee the resulting block will actually be seen by the network, as that farmer may:

1. Be offline
2. Be under attack or eclipsed
3. Be unreachable by the network
4. Could be acting maliciously 
5. Could have been bribed

* In the case of no solution, what do we do?

In the absence of any other rules, we would assume that all nodes who have the challenge piece would begin grinding on it. Now we have returned back to proof-of-work 1/3 of the time...

To prevent this, we allow nodes to extend existing solutions, by re-replicating them. The closer the solution is to the quality threshold, the less time it takes to extend. The time grows exponentially for each step in quality below the threshold challenge. For this to work, any farmer who has a close solution should start extending as soon as they figure that out. On average, this should bet two to four nodes per challenge. The minimum extension time needs to be set so that there is a high probability that an honest farmer would have already gossiped their solution (if they had it).

The other way to handle this problem is to allow any solution to be valid but to be of lower total quality. The obvious attack is to flood the chain with low quality solutions and quickly build a low quality chain faster than the slow, high quality honest chain. 

* Also, how do we handle forks in the case of multiple solutions?

Given the 33/33/33 distribution, what is the probability of a fork? 

Single Chain Architecture -- With single chain we will have a fork, o.a. every three blocks. In between we either have normal extensions or have to wait while a lower quality solution is extended.  

Parallel Chain Architecture -- The probability of a fork becomes much, much lower. Every time we have a multi-solution challenge, w.h.p. each solution will hash to a different chain. 1/1024 x 1/3 = 1 / 3072 vs 1/3, or every 3k blocks (.03 %).

Every time we get a fork, each node must decide which branch to favor. The rational approach would be to solve on both branches and then favor the side with the higher quality. 

The probability that both branches will be extended is (2/3) * (2/3) = 4/9. 
The probability that neither branch will be extend is (1/3) * (1/3) = 1/9. 
The probability that only one branch will be extended is 4/9 (how to calc?)

So, o.a., greater than 1/2 the time, we expect that one branch of the fork will stall and the network will then shift to the ongoing branch, taking the path of least resistance. This means that forks will naturally collapse given sufficient time.



* How do we measure chain quality?


## Issues 

1. How to think about minimum encoding time and the private chain attack?
2. Will the fork rate grow unbounded, or is there some equilibrium point?
3. How to make fractional quality adjustments?
4. Should proofs point to the last proof seen on the chain they hash to?
5. How do we make node id proximity matter in fork resolution?


## Anatomy of Attacks

1. Will the honest network converge to a single chain in the presence of forks?
2. What is the probability that forks will occur, and how to we deal with them?
3. To farm a private chain (and double spend), a farmer needs at least 51% of the storage resources. (to produce a chain faster)
4. What degree of parallelism is required to grind a private chain? (fast grinder)
5. Could this parallelism be used to augment existing storage (hybrid attack)
6. At what rate must a miner grinder to gain an advantage over the honest farmer? (slow grinder)
7. Is it possible to gain an advantage by retaining and solving on all branches of a fork? (simulation attack)
8. Is it possible to rewrite long sequences of history (long range attack)
9. Is their any advantage for selfish farming?
10. Is their any advantage for joining a farming pool or building a farming center? (Vitalik article)


1. Will the honest network converge in the presence of naturally occurring forks?

For any challenge there is a 33/33/33 prob of a 0/1/1+ valid solutions from the honest network.
We expect to see a stall, o.a. every three blocks. On stall recovery, we expect to see a fork.
We expect to see a single solution, normal chain growth, every three blocks.
We expect to see multiple solutions, and forks, every three blocks.

## Simulation Problem

In the event of an honest fork, how does a farmer choose one branch over the other?
They favor the branch that has the highest quality.

In proof of work branches would die off naturally because you can only mine on one chain at a time.

Do we have something similar with culling? If there 

Is there an e-advantage for retaining all chains and farming the one that is most favorable to you.
Each rational farmer would track all chains and attempt to solve on all of them

But all branches will eventually stall, so why not just switch to next best branch 

Lookback parameter?



## Security Caveats

1. How long does the minimum encoding delay need to be? So that the honest node may evaluate and release a solution before a parallel attacker can generate a better solution using only computation? Specifically, could an honest farmer use a raspberry pi (4) with a 1 TB HDD and a 100 mbps internet connection build a chain faster than a grinder node.
2. If the encoding time is too short the attacker can encode a private chain faster than the honest network.
3. If the encoding time is too long, the honest node will not be able to plot in a reasonable amount of time.
4. If the encoding time is not long enough, the attacker could grind out enough solutions in parallel to 

### A Double Spending Attack

How do we do a double spending attacking in BTC? 

1) Attacker spends some BTC
2) Attacker begins mining a private chain
3) Attacker waits for receipt of goods
4) Attacker then releases the private chain
5) This assumes several blocks can be released within the block interval

How would you do this in Subspace?

Single Chain

Parallel Chains

1) Attacker spends some SSC
2) Attacker begins farming/mining a private chain
3) Attacker waits for receipt of goods
4) Attacker releases the private chain

But there isn't just one chain, there are many.