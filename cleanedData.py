from countries import countries
combined = 'combined_url.csv'
cleaned_data = 'cleaned_data.csv'

bm = ('benign', 'malicious')
read_count = 0
write_count = 0
with open(combined, 'r') as combined, open(cleaned_data, 'w') as cleaned:

    file_in = combined.readlines()

    for line in file_in:
        read_count += 1
        file_out = line.replace("'", '')
        file_out_split = file_out.split("|")

        if file_out_split[0] == 'url':
            cleaned.write(file_out)
            write_count += 1
        elif any(c in file_out_split[-1] for c in bm):
            # change country code to a integer
            country_code = file_out_split[16]
            country_code = country_code.replace("_", " ")
            try:
                ranking = countries[country_code]
                file_out_split[13] = ranking
            except KeyError:
                file_out_split[13] = 0

            output = '|'.join(str(e) for e in file_out_split)
            cleaned.write(output)
            write_count += 1

Number_records_dropped = read_count - write_count
print(Number_records_dropped, " records dropped due to bad fields")
