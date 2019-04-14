import pandas as pd


classifierErrorsFP = 'classifierErrorsFP.csv'
classifierErrorsFN = 'classifierErrorsFN.csv'

FP_errors = pd.read_csv(classifierErrorsFP, delimiter='|', header=0)
FN_errors = pd.read_csv(classifierErrorsFN, delimiter='|', header=0)

#
# analyze FP errors (benign urls that were classified as malicious)
#
print('False Positive Errors')
len_of_url = FP_errors[(FP_errors['length_of_url'] >= 98) & (FP_errors['length_of_url'] <= 106)]
print('count of URLS with a length_of_url matching between 98 and 106 inclusive: ' + str(len_of_url.shape[0]))

number_of_dots = FP_errors[(FP_errors['number_of_dots'] >= 3)& (FP_errors['number_of_dots'] <= 4)]
print('count of URLS with a number_of_dots equal to 3 or 4: ' + str(number_of_dots.shape[0]))

length_of_directory = FP_errors[(FP_errors['length_of_directory'] >= 30) & (FP_errors['length_of_directory'] <= 42)]
print('count of URLS with a length_of_directory between 30 and 42: ' + str(length_of_directory.shape[0]))

length_of_domain = FP_errors[(FP_errors['length_of_domain'] >= 20) & (FP_errors['length_of_domain'] <= 23)]
print('count of URLS with a length_of_domain between 20 and 23 inclusive: ' + str(length_of_domain.shape[0]))

words_in_domain = FP_errors[(FP_errors['words_in_domain'] >= 3) & (FP_errors['words_in_domain'] <= 4)]
print('count of URLS with a words_in_domain equal 3 or 4: ' + str(words_in_domain.shape[0]))

has_alexa_rank = FP_errors[(FP_errors['has_alexa_rank'] == 0)]
print('count of URLS with a has_alexa_rank of 0: ' + str(has_alexa_rank.shape[0]))

country_code = FP_errors[(FP_errors['country_code'] != 225)]
print('count of URLS with a country_code not equal to 225 United States: ' + str(country_code.shape[0]))

words = FP_errors[(FP_errors['words'] >= 11) & (FP_errors['words'] <= 14)]
print('count of URLS with words between 11 and 14 inclusive: ' + str(words.shape[0]))

length_of_largest_domain_token = FP_errors[(FP_errors['length_of_largest_domain_token'] >= 10)
                                           & (FP_errors['length_of_largest_domain_token'] <= 12)]
print('count of URLS with length_of_largest_domain_token between 10 and 12: '
      + str(length_of_largest_domain_token.shape[0]))

length_of_largest_path_token = FP_errors[(FP_errors['length_of_largest_path_token'] >= 17)
                                           & (FP_errors['length_of_largest_path_token'] <= 18)]
print('count of URLS with length_of_largest_path_token between 17 and 18: '
      + str(length_of_largest_path_token.shape[0]))

len_of_filename = FP_errors[(FP_errors['len_of_filename'] >= 13) & (FP_errors['len_of_filename'] <= 14)]
print('count of URLS with len_of_filename between 13 and 14 inclusive: ' + str(len_of_filename.shape[0]))

num_delims_in_filename = FP_errors[(FP_errors['num_delims_in_filename'] < 3)]
print('count of URLS with num_delims_in_filename less than 3: ' + str(num_delims_in_filename.shape[0]))

length_of_arguments = FP_errors[(FP_errors['length_of_arguments'] >= 18) & (FP_errors['length_of_arguments'] <= 32)]
print('count of URLS with length_of_arguments between 18 and 32 inclusive: ' + str(length_of_arguments.shape[0]))

length_of_largest_variable = FP_errors[(FP_errors['length_of_largest_variable'] > 5)
                                       & (FP_errors['length_of_largest_variable'] <= 22)]


#
# analyze FN errors (malicious urls that were classified as benign)
#
print('False Negative Errors')

len_of_url = FN_errors[(FN_errors['length_of_url'] > 83) & (FN_errors['length_of_url'] < 107)]
print('count of URLS with a length_of_url matching between 83 and 107: ' + str(len_of_url.shape[0]))

number_of_dots = FN_errors[(FN_errors['number_of_dots'] == 2)]
print('count of URLS with a number_of_dots equal 2: ' + str(number_of_dots.shape[0]))

length_of_directory = FN_errors[(FN_errors['length_of_directory'] > 39) & (FN_errors['length_of_directory'] < 68)]
print('count of URLS with a length_of_directory between 39 and 68: ' + str(length_of_directory.shape[0]))

length_of_domain = FN_errors[(FN_errors['length_of_domain'] >= 11) & (FN_errors['length_of_domain'] <= 15)]
print('count of URLS with a length_of_domain between 11 and 15 inclusive: ' + str(length_of_domain.shape[0]))

words_in_domain = FN_errors[(FN_errors['words_in_domain'] == 2)]
print('count of URLS with a words_in_domain equal 2: ' + str(words_in_domain.shape[0]))

has_alexa_rank = FN_errors[(FN_errors['has_alexa_rank'] == 1)]
print('count of URLS with a has_alexa_rank of 1: ' + str(has_alexa_rank.shape[0]))

country_code = FN_errors[(FN_errors['country_code'] == 225)]
print('count of URLS with a country_code equal to 225 United States: ' + str(country_code.shape[0]))

words = FN_errors[(FN_errors['words'] >= 16) & (FN_errors['words'] <= 18)]
print('count of URLS with words between 16 and 18 inclusive: ' + str(words.shape[0]))

length_of_largest_domain_token = FN_errors[(FN_errors['length_of_largest_domain_token'] >= 7.75)
                                           & (FN_errors['length_of_largest_domain_token'] <= 10)]
print('count of URLS with length_of_largest_domain_token between 7.75 and 10: '
      + str(length_of_largest_domain_token.shape[0]))

length_of_largest_path_token = FN_errors[(FN_errors['length_of_largest_path_token'] >= 25)
                                         & (FN_errors['length_of_largest_path_token'] <= 41)]
print('count of URLS with length_of_largest_path_token between 7.75 and 10: '
      + str(length_of_largest_path_token.shape[0]))

len_of_filename = FN_errors[(FN_errors['len_of_filename'] >= 37) & (FN_errors['len_of_filename'] <= 63)]
print('count of URLS with len_of_filename between 37 and 63 inclusive: ' + str(len_of_filename.shape[0]))

num_delims_in_filename = FN_errors[(FN_errors['num_delims_in_filename'] > 3)]
print('count of URLS with num_delims_in_filename greater than 3: ' + str(num_delims_in_filename.shape[0]))

length_of_arguments = FN_errors[(FN_errors['length_of_arguments'] >= 10) & (FN_errors['length_of_arguments'] <= 19)]
print('count of URLS with length_of_arguments between 10 and 19 inclusive: ' + str(length_of_arguments.shape[0]))

length_of_largest_variable = FN_errors[(FN_errors['length_of_largest_variable'] > 1)
                                       & (FN_errors['length_of_largest_variable'] <= 11)]
print('count of URLS with length_of_largest_variable between 1 and 11 inclusive: '
      + str(length_of_largest_variable.shape[0]))

"""
Write out a files of URLS for selected features that could have large impact on False P / False N 
"""

FP_alexa = FP_errors[FP_errors['has_alexa_rank'] == 0]
FP_alexa.to_csv('FP_Alexa_Rank_0.csv', header=False)
FP_country = FP_errors[(FP_errors['country_code'] != 225)]
FP_country.to_csv('FP_Country_NE255.csv', header=False)

FN_alexa = FN_errors[FN_errors['has_alexa_rank'] == 1]
FN_alexa.to_csv('FN_Alexa_Rank_1.csv', header=True)
FN_country = FN_errors[(FN_errors['country_code'] == 225)]
FN_country.to_csv('FN_Country_EQ255.csv', header=True)

FN_alexa_country = FN_errors[(FN_errors['has_alexa_rank'] == 1) & (FN_errors['country_code'] == 225)]
FN_alexa_country.to_csv('FN_alexa_country.csv', header=True)
print(FN_alexa_country.shape[0])


# searchfor = ['ancestry', 'amazon']
searchfor = ['ancestry', 'amazon.co.uk']
FN_amazon_ancestry = FN_errors[FN_errors['url'].str.contains('|'.join(searchfor))]
FN_amazon_ancestry.to_csv('FN_amazon_ancestry.csv', header=True)
print(FN_amazon_ancestry.shape[0])

# read in the deduped csv file
deduped = 'cleaned_deduped.csv'
deduped_df = pd.read_csv(deduped, delimiter='|', header=0)

# find the records that need to be dropped
to_drop = deduped_df[(deduped_df['url'].str.contains('|'.join(searchfor)) & (deduped_df['class'] == 'malicious'))]
print(to_drop.shape[0])

# concatenate the to_drop and the deduped data frames, and drop all duplicated keep=False drops
# ALL of the records that are labeled as duplicates
dropped = pd.concat([deduped_df, to_drop]).drop_duplicates(keep=False)
dropped.to_csv('dropped.csv', sep='|', index=None)


