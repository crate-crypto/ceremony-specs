# Reference Implementation for Powers of Tau

## Introduction

To understand how the ceremony works at a high level, one can check out `ceremony_test.py` and `actors.py`.

To understand what API should be implemented for the specs, see `sdk.py`

### FAQ

**Can an implementation contribute to only one of the ceremonies or half of them?**

We do not allow this for two reasons; 1. This adds extra complexity. 2. The ceremonies are small enough that one should be able to contribute to all four of them within a reasonable amount of time.

Also, when someone says they contributed to the Ceremony, it would be desirable for this to mean that they participated to all four ceremonies. 

**Can a single participant DOS the ceremony by taking a long time to contribute?**

There will be a reasonable upper bound on how long a participant should take to contribute to all four ceremonies. Once that bound has been surpassed, the participant is disconnected.

**Can a single person sybil attack the ceremony in order to DOS?**

The attack here is that Bob enters the queue 10,000 times and gets disconnected each time. If the upper bound is 1minute, then Bob could waste 10,000 minutes of time in the ceremony. Users may disconnect because they are waiting for so long.

This is somewhat mitigated by enforcing that users need to authenticate themselves before joining the queue. Of course it is not wholly mitigated as Bob could be farming 10,000 github accounts as we speak. Also note that if the upper bound is set low enough, then for Bob to make a significant DOS attempt, they would need to have more accounts.

This is one motivation to allow optimistic contributions, as the upper bound could be made lower.

**Given that the ceremonies need to be distinct, can a single participant contribute the same randomness to all ceremonies?**

Yes. We can class this as a dishonest party. Our definition of an honest party, is one whom contributes to the ceremonies, throws away their secret and contributes to each ceremony with different randomness.

**Given that you do not check for different randomness, why do you check for the randomness not being zero?**

The randomness being zero effectively cancels out everyone elses contribution. So even if someone did contribute honestly, a dishonest party could invalidate their contribution. The randomness being distinct does not effect honest participants.