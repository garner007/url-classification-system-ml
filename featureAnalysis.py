import pandas as pd


cleanedDeduped = 'cleaned_deduped.csv'


data_csv = pd.read_csv(cleanedDeduped, delimiter='|', header=0)

benign = data_csv[data_csv['class'] == 'benign']
malicious = data_csv[data_csv['class'] == 'malicious']

#
# malicious URL feature Analysis)
#

print('malicious URL Analysis')
len_of_url_m = malicious[(malicious['length_of_url'] >= 98) & (malicious['length_of_url'] <= 106)]
print('count of URLS with a length_of_url matching between 98 and 106 inclusive: ' + str(len_of_url_m.shape[0]))

number_of_dots_m = malicious[(malicious['number_of_dots'] >= 3)& (malicious['number_of_dots'] <= 4)]
print('count of URLS with a number_of_dots equal to 3 or 4: ' + str(number_of_dots_m.shape[0]))

length_of_directory_m = malicious[(malicious['length_of_directory'] >= 30) & (malicious['length_of_directory'] <= 42)]
print('count of URLS with a length_of_directory between 30 and 42: ' + str(length_of_directory_m.shape[0]))

length_of_domain_m = malicious[(malicious['length_of_domain'] >= 20) & (malicious['length_of_domain'] <= 23)]
print('count of URLS with a length_of_domain between 20 and 23 inclusive: ' + str(length_of_domain_m.shape[0]))

words_in_domain_m = malicious[(malicious['words_in_domain'] >= 3) & (malicious['words_in_domain'] <= 4)]
print('count of URLS with a words_in_domain equal 3 or 4: ' + str(words_in_domain_m.shape[0]))

has_alexa_rank_m = malicious[(malicious['has_alexa_rank'] == 0)]
print('count of URLS with a has_alexa_rank of 0: ' + str(has_alexa_rank_m.shape[0]))

country_code_m = malicious[(malicious['country_code'] != 225)]
print('count of URLS with a country_code not equal to 225 United States: ' + str(country_code_m.shape[0]))

words_m = malicious[(malicious['words'] >= 11) & (malicious['words'] <= 14)]
print('count of URLS with words between 11 and 14 inclusive: ' + str(words_m.shape[0]))

length_of_largest_domain_token_m = malicious[(malicious['length_of_largest_domain_token'] >= 10)
                                           & (malicious['length_of_largest_domain_token'] <= 12)]
print('count of URLS with length_of_largest_domain_token between 10 and 12: '
      + str(length_of_largest_domain_token_m.shape[0]))

length_of_largest_path_token_m = malicious[(malicious['length_of_largest_path_token'] >= 17)
                                           & (malicious['length_of_largest_path_token'] <= 18)]
print('count of URLS with length_of_largest_path_token between 17 and 18: '
      + str(length_of_largest_path_token_m.shape[0]))

len_of_filename_m = malicious[(malicious['len_of_filename'] >= 13) & (malicious['len_of_filename'] <= 14)]
print('count of URLS with len_of_filename between 13 and 14 inclusive: ' + str(len_of_filename_m.shape[0]))

num_delims_in_filename_m = malicious[(malicious['num_delims_in_filename'] < 3)]
print('count of URLS with num_delims_in_filename less than 3: ' + str(num_delims_in_filename_m.shape[0]))

length_of_arguments_m = malicious[(malicious['length_of_arguments'] >= 18) & (malicious['length_of_arguments'] <= 32)]
print('count of URLS with length_of_arguments between 18 and 32 inclusive: ' + str(length_of_arguments_m.shape[0]))

length_of_largest_variable_m = malicious[(malicious['length_of_largest_variable'] > 5)
                                       & (malicious['length_of_largest_variable'] <= 22)]
print('count of URLS with length_of_largest_variable between 1 and 11 inclusive: '
      + str(length_of_largest_variable_m.shape[0]))

#
# analyze FN errors (malicious urls that were classified as benign)
#
print('Benign Feature Analysis')

len_of_url_b = benign[(benign['length_of_url'] > 83) & (benign['length_of_url'] < 107)]
print('count of URLS with a length_of_url matching between 83 and 107: ' + str(len_of_url_b.shape[0]))

number_of_dots_b = benign[(benign['number_of_dots'] == 2)]
print('count of URLS with a number_of_dots equal 2: ' + str(number_of_dots_b.shape[0]))

length_of_directory_b = benign[(benign['length_of_directory'] > 39) & (benign['length_of_directory'] < 68)]
print('count of URLS with a length_of_directory between 39 and 68: ' + str(length_of_directory_b.shape[0]))

length_of_domain_b = benign[(benign['length_of_domain'] >= 11) & (benign['length_of_domain'] <= 15)]
print('count of URLS with a length_of_domain between 11 and 15 inclusive: ' + str(length_of_domain_b.shape[0]))

words_in_domain_b = benign[(benign['words_in_domain'] == 2)]
print('count of URLS with a words_in_domain equal 2: ' + str(words_in_domain_b.shape[0]))

has_alexa_rank_b = benign[(benign['has_alexa_rank'] == 1)]
print('count of URLS with a has_alexa_rank of 1: ' + str(has_alexa_rank_b.shape[0]))

country_code_b = benign[(benign['country_code'] == 225)]
print('count of URLS with a country_code equal to 225 United States: ' + str(country_code_b.shape[0]))

words_b = benign[(benign['words'] >= 16) & (benign['words'] <= 18)]
print('count of URLS with words between 16 and 18 inclusive: ' + str(words_b.shape[0]))

length_of_largest_domain_token_b = benign[(benign['length_of_largest_domain_token'] >= 7.75)
                                           & (benign['length_of_largest_domain_token'] <= 10)]
print('count of URLS with length_of_largest_domain_token between 7.75 and 10: '
      + str(length_of_largest_domain_token_b.shape[0]))

length_of_largest_path_token_b = benign[(benign['length_of_largest_path_token'] >= 25)
                                           & (benign['length_of_largest_path_token'] <= 41)]
print('count of URLS with length_of_largest_path_token between 7.75 and 10: '
      + str(length_of_largest_path_token_b.shape[0]))

len_of_filename_b = benign[(benign['len_of_filename'] >= 37) & (benign['len_of_filename'] <= 63)]
print('count of URLS with len_of_filename between 37 and 63 inclusive: ' + str(len_of_filename_b.shape[0]))

num_delims_in_filename_b = benign[(benign['num_delims_in_filename'] > 3)]
print('count of URLS with num_delims_in_filename greater than 3: ' + str(num_delims_in_filename_b.shape[0]))

length_of_arguments_b = benign[(benign['length_of_arguments'] >= 10) & (benign['length_of_arguments'] <= 19)]
print('count of URLS with length_of_arguments between 10 and 19 inclusive: ' + str(length_of_arguments_b.shape[0]))

length_of_largest_variable_b = benign[(benign['length_of_largest_variable'] > 1)
                                       & (benign['length_of_largest_variable'] <= 11)]
print('count of URLS with length_of_largest_variable between 1 and 11 inclusive: '
      + str(length_of_largest_variable_b.shape[0]))
