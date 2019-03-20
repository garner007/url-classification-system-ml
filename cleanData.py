from countries import countries
combined = 'combined_url.csv'
cleaned_data = 'cleaned_data.csv'
dropped_data = 'invalid.csv'

bm = ('benign', 'malicious')
read_count = 0
write_count = 0
with open(combined, 'r') as combined, open(cleaned_data, 'w') as cleaned, open(dropped_data, 'w') as dropped:

    file_in = combined.readlines()

    for line in file_in:
        read_count += 1
        # some of the fields have a ' in them, so need to get rid of them
        file_out = line.replace("'", '')
        file_out_split = file_out.split("|")

        # writing file header back out
        if file_out_split[0] == 'url':
            cleaned.write(file_out)
            dropped.write(file_out)
            write_count += 1
        # all of the remainder of the records
        # all records should have benign or malicious as the class
        elif any(c in file_out_split[-1] for c in bm):
            # change country code to a integer
            country_code = file_out_split[16]
            country_code = country_code.replace("_", " ")
            try:
                # see if we can find a ranking for the country
                ranking = countries[country_code]
                file_out_split[13] = ranking
            except KeyError:
                # non-standard country name found, so set it to 0
                file_out_split[13] = 0

            output = '|'.join(str(e) for e in file_out_split)
            cleaned.write(output)
            write_count += 1
        else:
            # during the extract process, some records on the Benign / Malicious file had | as delimiters,
            # causing issue with the split; we will just get rid of those now
            # and write to file for possible analysis
            dropped.write(line)

Number_records_dropped = read_count - write_count
print(Number_records_dropped, " records dropped due to bad fields")
