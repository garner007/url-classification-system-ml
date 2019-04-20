# URL Classification using NaiveBayes Data Mining. 
This is a code base for my capstone Data Mining and Cybersecurity class.  It is designed to make predictions on whether 
or not a URL is benign or malicious, without accessing the web page directly.  

Code developed using Ubuntu 18.04 and Python 3.6

## Description of Modules
### loadAlexaDB.py 
    - downloads the top 1m webpages from Alexa and loads the csv to a sqlite database
### extract_features.py
    - reads in the url files (benign.csv and merged_malware.csv)
    - processes these records through **vector_creator.py** to vectorize the url
    - vector is written out to **combined_url.csv**
### cleanAndDedupData.py.py
    - reads the **combined_url.csv** data and checks for data issues that were found causing issues , and 
        corrects them or drops those records
    - removed duplicate URLs from the file
    - creates **cleaned_data.csv** for use in further processing
### findBestK.py
    - read in the **cleaned_data.csv** , and used SelectKBest feature selection, running n-times as determined by 
        the number of features on the file.  
    - each of the k-best values is run through cross validation, to determine which would produce the best model. 
    - the feature mask for the k-best that produces the best model is then written out, to be used to produce the full
        model and for using in the predictor module
###  trainFullBayesModel.py
    - using the feature mask from **findBestK.py** , cross validation is run again to produce average statistics
    - ROC curve, Confusion Matrix and accuracy scores are produces
    - writes out files for false negative and false positive classifier errors
    - model is saved to a pickle file, to be used again in the **predictor.py** 
###  trainFullBayesModelAllFeatures.py
    - runs the same as the trainFullBayesModel with the exception that it uses all of the features on the file
    - also does not write out classifier errors
###  DecisionForest.py
    - creates a classifier using the cleaned, deduped data using the Decision Tree model
    - ROC curve, Confusion Matrix and accuracy scores are produces
###  randomForest.py
    - creates a classifier using the cleaned, deduped data using the Random Forest model
    - ROC curve, Confusion Matrix and accuracy scores are produces
###  predictor.py
    - Asks for URL for testing; runs the url through **vector_creator.py** 
    - returned vector is run throught he naive model and prediciton is produced. 
### dataAnalysis.py
    - creates statistical informaiton from the benign and malicious groups of deduped data and writes out to a CSV
    - counts the number of records on the original cleaned file and the dedupped file for comparison. 
### errorAnalysis.py
    - uses the false positive and false negative classifier errors to perform analysis
    - creates counts of the number of records from each of the files that fit criteria for the features
        to help determine where errors may be coming from 
    - using analysis of those errors, addition csv files are created to further analyze the largest of the error for 
        trends 
    - after analysis was done, records are removed for further testing and analysis. 
### featureAnalysis.py
    - creates counts of the number of records from the deduped file that fit criteria for the features
        to allow for analysis

 