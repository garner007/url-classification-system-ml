import pandas as pd


classifierErrorsFP = 'classifierErrorsFP.csv'
classifierErrorsFN = 'classifierErrorsFN.csv'

FP_errors = pd.read_csv(classifierErrorsFP, delimiter=',', header=0)
FN_errors = pd.read_csv(classifierErrorsFN, delimiter=',', header=0)

# analyze FP errors (benign urls that were classified as malicious)
print('False Positive Errors')
len_of_url = FP_errors[(FP_errors['length_of_url'] > 52) & (FP_errors['length_of_url'] < 95)]
print('count of URLS with a length_of_url matching Malicious statistics: ' + str(len_of_url.shape[0]))

length_of_directory = FP_errors[(FP_errors['length_of_directory'] > 10) & (FP_errors['length_of_directory'] < 55)]
print('count of URLS with a length_of_directory matching Malicious statistics: ' + str(length_of_directory.shape[0]))

length_of_domain = FP_errors[(FP_errors['length_of_domain'] > 13) & (FP_errors['length_of_domain'] < 22)]
print('count of URLS with a length_of_domain matching Malicious statistics: ' + str(length_of_domain.shape[0]))

has_alexa_rank = FP_errors[(FP_errors['has_alexa_rank'] == 0)]
print('count of URLS with a has_alexa_rank of 0: ' + str(has_alexa_rank.shape[0]))

country_code = FP_errors[(FP_errors['country_code'] != 225)]
print('count of URLS with a country_code not equal to 225 United States: ' + str(country_code.shape[0]))

words = FP_errors[(FP_errors['words'] > 9) & (FP_errors['words'] < 16)]
print('count of URLS with words matching Malicious statistics: ' + str(words.shape[0]))


len_of_filename = FP_errors[(FP_errors['len_of_filename'] > 9) & (FP_errors['len_of_filename'] < 16)]
print('count of URLS with len_of_filename matching Malicious statistics: ' + str(len_of_filename.shape[0]))


#
# analyze FN errors (malicious urls that were classified as benign)
#
print('False Negative Errors')
len_of_url = FN_errors[(FN_errors['length_of_url'] > 83) & (FN_errors['length_of_url'] < 113)]
print('count of URLS with a length_of_url matching Malicious statistics: ' + str(len_of_url.shape[0]))

length_of_directory = FN_errors[(FN_errors['length_of_directory'] > 55)]
print('count of URLS with a length_of_directory matching Malicious statistics: ' + str(length_of_directory.shape[0]))

length_of_domain = FN_errors[(FN_errors['length_of_domain'] > 10) & (FN_errors['length_of_domain'] < 10)]
print('count of URLS with a length_of_domain matching Malicious statistics: ' + str(length_of_domain.shape[0]))

has_alexa_rank = FN_errors[(FN_errors['has_alexa_rank'] == 1)]
print('count of URLS with a has_alexa_rank of 1: ' + str(has_alexa_rank.shape[0]))

country_code = FN_errors[(FN_errors['country_code'] == 225)]
print('count of URLS with a country_code equal to 225 United States: ' + str(country_code.shape[0]))

words = FN_errors[(FN_errors['words'] > 13) & (FN_errors['words'] < 18)]
print('count of URLS with words matching Malicious statistics: ' + str(words.shape[0]))


len_of_filename = FN_errors[(FN_errors['len_of_filename'] > 14)]
print('count of URLS with len_of_filename matching Malicious statistics: ' + str(len_of_filename.shape[0]))
