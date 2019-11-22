import argparse, sys, time, os
import math
import hashlib
import array
import numpy
from tqdm import tqdm
import struct
import random

HASH_SIZE = 32

def generate_dict_for(alphabet, pwd_len):
    current = bytearray(alphabet[0]*pwd_len, 'utf-8')
    num_possible_pwds = round(math.pow(len(alphabet), pwd_len))

    # Init hash dict
    dt = numpy.dtype={'names':('hash', 'pwd'), 'formats':((numpy.void, HASH_SIZE), (numpy.void, 5))}
    hash_dict = numpy.empty(num_possible_pwds, dtype=dt)

    with tqdm(total=num_possible_pwds, unit='pwd', unit_scale=True) as pbar:
        for i in range(num_possible_pwds):
            # Hash and store password
            hash256 = hashlib.sha256(current).digest()
            hash_dict[i]['hash'] = hash256
            hash_dict[i]['pwd'] = current
            
            # Generate next password
            for char_idx in reversed(range(pwd_len)):
                idx_in_alph = alphabet.index(chr(current[char_idx]))
                if idx_in_alph < len(alphabet)-1:
                    current[char_idx] = ord(alphabet[idx_in_alph+1])
                    break
                else:
                    current[char_idx] = ord(alphabet[0])
            
            # Progress bar
            pbar.update()

    return hash_dict

def save(hash_dict, prefix, segments):
        dict_map = list()
        segment_entries = round(len(hash_dict)/segments)
        segment_id_length = math.ceil(math.log10(segments))

        # Save hashes
        print("Saving hashes ...")
        
        segment_id = 0
        with tqdm(total=len(hash_dict), unit='hash', unit_scale=True) as pbar:
            file = None
            for i, x in enumerate(hash_dict):
                if i % segment_entries == 0:
                    if file != None: file.close()
                    file = open("{}-{}.data".format(prefix, str(segment_id).zfill(segment_id_length)), 'w+b')
                    segment_id += 1
                    dict_map.append(x['hash'])
                file.write(x['hash'])
                pbar.update()
            file.close()

        print("Saving passwords ...")
        segment_id = 0
        with tqdm(total=len(hash_dict), unit='pwd', unit_scale=True) as pbar:
            file = None
            for i,x in enumerate(hash_dict):
                if i % segment_entries == 0:
                    if file != None: file.close()
                    file = open("{}-pwds-{}.data".format(prefix, str(segment_id).zfill(segment_id_length)), 'w+b')
                    segment_id += 1
                    dict_map.append(x['hash'])
                file.write(x['pwd'])
                pbar.update()

        print("Saving map ...")
        with open("{}-map.data".format(prefix), 'w+b') as f:
            with tqdm(total=len(dict_map), unit_scale=True) as pbar:
                for x in dict_map:
                    f.write(bytes(x))
                    pbar.update()

def find(searched, prefix, segments, n_passwords):
    segment_entries = round(n_passwords/segments)
    segment_id = -1
    segment_id_length = math.ceil(math.log10(segments))

    with open("{}-map.data".format(prefix), 'rb') as f:
        for i in range(segments):
            if searched < f.read(HASH_SIZE): break
            segment_id += 1

    pwd_offset = 0
    with open("{}-{}.data".format(prefix, str(segment_id).zfill(segment_id_length)), 'rb') as f:
        hash = f.read(HASH_SIZE)
        while len(hash) == HASH_SIZE:
            if hash == searched: break
            hash = f.read(HASH_SIZE)
            pwd_offset += 1

    if len(hash) != HASH_SIZE: return None
    
    with open("{}-pwds-{}.data".format(prefix, str(segment_id).zfill(segment_id_length)), 'rb') as f:
        f.read(pwd_offset*5)
        return f.read(5).decode('utf-8')

def rand_string(alphabet, length):
    return ''.join(random.choice(alphabet) for i in range(length))

def gen_rand_str_set(alphabet, length, amount):
    res = set()
    while len(res) < amount:
        res.add(rand_string(alphabet, length))
    return res

################
# CLI Commands #
################

def cmd_create(argv):
    parser = argparse.ArgumentParser(description='Creates a lookup hash dictionary for all possible passwords')
    parser.add_argument('alphabet', type=str, help='The alphabet the passwords are generated from')
    parser.add_argument('length', type=int, help='The length of the passwords')
    parser.add_argument('-p', '--prefix', default="./dict/dict", type=str,help="The prefix for all generated files")
    parser.add_argument('-s', '--segments', default=16, type=int ,help="Number of segments to split the dictionary in")
    args = parser.parse_args(argv)

    if not os.path.isdir(os.path.dirname(args.prefix)):
        print("Directory '{}' doesn't exist".format(os.path.dirname(args.prefix)))
        return 

    print("Generating dict ...")
    hash_dict = generate_dict_for(args.alphabet, args.length)
    
    print("Sorting dict ...")
    start = time.time()
    hash_dict.sort()
    print("{}s".format((time.time()-start)))

    save(hash_dict, args.prefix, args.segments)

def cmd_hash(argv):
    parser = argparse.ArgumentParser(description='Generate hash for input')
    parser.add_argument('input', type=str, help='The input')
    args = parser.parse_args(argv)

    print(hashlib.sha256(bytearray(args.input, 'utf-8')).hexdigest())

def cmd_find(argv):
    parser = argparse.ArgumentParser(description='Find password that generates a given hash')
    parser.add_argument('hash', type=str, help='The hash of the searched for password')
    parser.add_argument('alphabet', type=str, help='The alphabet the passwords can be from')
    parser.add_argument('length', type=int, help='The length of the password')
    parser.add_argument('-p', '--prefix', default="./dict/dict", type=str,help="The prefix for all generated files")
    parser.add_argument('-s', '--segments', default="16", type=int ,help="Number of segments the dictionary is split into")
    args = parser.parse_args(argv)

    start = time.time()

    num_possible_pwds = math.pow(len(args.alphabet),args.length)    
    pwd = find(bytes.fromhex(args.hash), args.prefix, args.segments, num_possible_pwds)

    if pwd == None: print("Couldn't find hash ({}s)".format(time.time()-start))
    else: print("Password is: {} ({}s)".format(pwd, time.time()-start))

def cmd_benchmark(argv):
    parser = argparse.ArgumentParser(description='Find password that generates a given hash')
    parser.add_argument('alphabet', type=str, help='The alphabet the passwords can be from')
    parser.add_argument('length', type=int, help='The length of the password')
    parser.add_argument('-p', '--prefix', default="./dict/dict", type=str,help="The prefix for all generated files")
    parser.add_argument('-s', '--segments', default=16, type=int ,help="Number of segments the dictionary is split into")
    parser.add_argument('-n', '--num_tests', default=100, type=int ,help="Number of tests")
    args = parser.parse_args(argv)

    total_time = 0
    num_possible_pwds = round(math.pow(len(args.alphabet),args.length))
    test_cases = gen_rand_str_set(args.alphabet, args.length, args.num_tests)
    for case in tqdm(test_cases, unit='test', unit_scale=True):
        hash256 = hashlib.sha256(bytes(case, 'utf-8')).digest()

        # Benchmark find method
        start = time.time()
        pwd = find(hash256, args.prefix, args.segments, num_possible_pwds)
        total_time += time.time()-start

        # Check if password is correct
        if pwd != case:
            print("Error: ", pwd, case, i, bytes(hash256).hex())
            return

    print("total={}s, avrg={}s".format(round(total_time,4), round(total_time/args.num_tests,4)))
    
########
# Main #
########

CMD_CREATE = 'create'
CMD_HASH = 'hash'
CMD_FIND = 'find'
CMD_BENCHMARK = 'bench'
COMMANDS = [CMD_CREATE, CMD_HASH, CMD_FIND, CMD_BENCHMARK]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Creates a lookup hash dictionary for all possible passwords')
    parser.add_argument('command', type=str, choices=COMMANDS, help='The subcommand to run')
    args = parser.parse_args(sys.argv[1:2])
 
    if args.command == CMD_CREATE:
        cmd_create(sys.argv[2:])
    if args.command == CMD_HASH:
        cmd_hash(sys.argv[2:])
    if args.command == CMD_FIND:
        cmd_find(sys.argv[2:])
    if args.command == CMD_BENCHMARK:
        cmd_benchmark(sys.argv[2:])