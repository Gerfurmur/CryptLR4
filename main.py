import HMAC
import OMAC
import truncated_MAC
import matplotlib.pyplot as plt
from datetime import datetime


msg_sizes = [0.1, 1, 10, 1024]
number_of_msg = 1000



def save(name='', fmt='png'):
    plt.savefig('{}.{}'.format(name, fmt), fmt='png')


def check_verify_func():
    h = HMAC.HMAC()
    h.set_key(b"the key of len16")
    print("key =", b"the key of len16".hex())
    htag = h.compute_mac(b"Here we are using HMAC based on SHA256!!")
    print("hmac res =", htag)
    print("verify = ", h.verify_mac(b"Here we are using HMAC bbsed on SHA256!!", htag))
    print("verify = ", h.verify_mac(b"Here we are using HMAC based on SHA256!!", htag))

    o = OMAC.OMAC()
    o.set_key(b"the key of len16")
    otag = o.compute_mac(b"Here we are using OMAC based on aes ecb!")
    print("omac res =", otag)
    print("verify = ", o.verify_mac(b"Here we are using OMAC bbsed on aes ecb!", otag))
    print("verify = ", o.verify_mac(b"Here we are using OMAC based on aes ecb!", otag))

    t = truncated_MAC.t_MAC()
    t.set_key(b"the key of len16")
    ttag = t.compute_mac(b"Here we are using OMAC based on aes ecb!")
    print("tmac res =", ttag)
    print("verify = ", t.verify_mac(b"Here we are using OMAC bbsed on aes ecb!", ttag))
    print("verify = ", t.verify_mac(b"Here we are using OMAC based on aes ecb!", ttag))


def graphicks():
    msg_1 = []
    msg_2 = []
    msg_3 = []
    msg_4 = []
    htimes = [0]*len(msg_sizes)
    otimes = [0]*len(msg_sizes)
    h = HMAC.HMAC()
    h.set_key(b"the key of len16")
    o = OMAC.OMAC()
    o.set_key(b"the key of len16")
    with open("books.txt") as readfile:
        data = readfile.read()
    for msg in range(number_of_msg):
        msg_1.append(data[msg*16:(msg+1)*16].encode())
        msg_2.append(data[msg*1024:(msg+1)*1024].encode())
        msg_3.append(data[msg*10240:(msg+1)*10240].encode())
    msg_4.extend([data[:1024*1024].encode()]*1000)
    for msg in range(number_of_msg):
        start_time = datetime.now()
        h.compute_mac(msg_1[msg])
        end_time = datetime.now()
        htimes[0] += (end_time - start_time).microseconds
        start_time = datetime.now()
        h.compute_mac(msg_2[msg])
        end_time = datetime.now()
        htimes[1] += (end_time - start_time).microseconds
        start_time = datetime.now()
        h.compute_mac(msg_3[msg])
        end_time = datetime.now()
        htimes[2] += (end_time - start_time).microseconds + (end_time - start_time).seconds * 1000000
        start_time = datetime.now()
        h.compute_mac(msg_4[msg])
        end_time = datetime.now()
        htimes[3] += (end_time - start_time).microseconds + (end_time - start_time).seconds * 1000000
    fig = plt.figure()
    ax = fig.add_subplot()
    ax.set_xscale('log')
    ax.plot(msg_sizes, htimes)
    ax.grid(True)
    ax.set_xlabel('size, Kbytes', fontsize=14)
    ax.set_ylabel('Time, mcs', fontsize=14)
    ax.set_title('HMAC time chart', loc='center')
    # save(name='HMAC time chart', fmt='png')
    plt.show()

    for msg in range(number_of_msg):
        start_time = datetime.now()
        o.compute_mac(msg_1[msg])
        end_time = datetime.now()
        otimes[0] += (end_time - start_time).microseconds
        start_time = datetime.now()
        o.compute_mac(msg_2[msg])
        end_time = datetime.now()
        otimes[1] += (end_time - start_time).microseconds
        start_time = datetime.now()
        o.compute_mac(msg_3[msg])
        end_time = datetime.now()
        otimes[2] += (end_time - start_time).microseconds + (end_time - start_time).seconds * 1000000
        start_time = datetime.now()
        o.compute_mac(msg_4[msg])
        end_time = datetime.now()
        otimes[3] += (end_time - start_time).microseconds + (end_time - start_time).seconds * 1000000
    otimes = [time / number_of_msg for time in otimes]
    fig = plt.figure()
    ax = fig.add_subplot()
    ax.set_xscale('log')  # log здесь - натуральный логарифм!
    ax.plot(msg_sizes, otimes)
    ax.grid(True)
    ax.set_xlabel('size, Kbytes', fontsize=14)
    ax.set_ylabel('Time, mcs', fontsize=14)
    ax.set_title('OMAC time chart', loc='center')
    # save(name='OMAC time chart', fmt='png')
    plt.show()


check_verify_func()

