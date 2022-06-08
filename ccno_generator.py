import random, optparse, sys

issuer_list = {
    "visa": ["4"],
    "mastercard": list(range(51, 56)) + list(range(2221, 2721)),
    "rupay": [60, 65, 81, 82, 508, 353, 356]
}

def luhn_check(card_no):
    card_list = []
    card_list[:0] = str(card_no)
    
    if len(card_list) == 16:
        sum_even = 0
        sum_odd = 0
        for i in range(0, 15, 2):
            sum_odd += int(card_list[15-i])
        for i in range(0, 15, 2):
            if (int(card_list[14-i]) * 2) > 9:
                num_list = []
                num_list[:0] = str(int(card_list[14-i]) * 2)
                sum_even += int(num_list[0]) + int(num_list[1])
            else:
                sum_even += int(card_list[14-i]) * 2
        if (sum_even + sum_odd) % 10 == 0:
            return True
        else:
            return False
    else:
        return False
    

def gen_card_no(card_issuer):
    if card_issuer in issuer_list.keys():
        bins = issuer_list[card_issuer]
        random_bin_index = random.randint(0, len(bins)-1)
        random_bin = bins[random_bin_index]
        card_success = False
        card_no = ""
        while not card_success:
            no_of_digits = 16 - len(str(random_bin))
            temp_card_number = []
            temp_card_number[:0] = str(random_bin)
            for counter in range(0, no_of_digits):
                digit = random.randint(0, 9)
                temp_card_number.append(str(digit))
            card_no = "".join(temp_card_number)
            card_success = luhn_check(card_no)
        return card_no
    elif card_issuer == "random":
        bins = []
        for card_issuer in issuer_list.keys():
            bins += issuer_list[card_issuer]
        random_bin_index = random.randint(0, len(bins)-1)
        random_bin = bins[random_bin_index]
        card_success = False
        card_no = ""
        while not card_success:
            no_of_digits = 16 - len(str(random_bin))
            temp_card_number = []
            temp_card_number[:0] = str(random_bin)
            for counter in range(0, no_of_digits):
                digit = random.randint(0, 9)
                temp_card_number.append(str(digit))
            card_no = "".join(temp_card_number)
            card_success = luhn_check(card_no)
        return card_no
    else:
        return 0
    

def main():
    parser = optparse.OptionParser(f"Script to generate valid card numbers.\n{__file__} -c 10 -o cards.txt -i visa\n* All arguments are optional and have default values.")
    parser.add_option("-c", "--count", default=100, dest="cards_count", help="Number of Cards to generate")
    parser.add_option("-o", "--output", default="cards.txt", dest="output_filename", help="Output file name")
    parser.add_option("-i", "--issuer", default="random", dest="issuer", help="Card issuer from visa, mastercard, rupay, random")
    
    (options, args) = parser.parse_args()
    
    output_data = []
    if (options.issuer not in issuer_list.keys()) and (options.issuer != "random"):
        parser.print_help()
        sys.exit(1)
    for i in range(0, int(options.cards_count)):
        output_data.append(gen_card_no(options.issuer))
    
    output = '\n'.join(output_data)
    
    with open(options.output_filename, "w") as f:
        f.write(output)
    
    print(f"[+] {options.cards_count} Cards written to '{options.output_filename}'")


if __name__ == "__main__":
    main()