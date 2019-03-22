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
### cleanData.py
    - reads the **combined_url.csv** data and checks for data issues that were found causing issues , and 
        corrects them or drops those records
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
    - model is saved to a pickle file, to be used again in the **predictor.py** 
###  predictor.py
    - Asks for URL for testing; runs the url through **vector_creator.py** 
    - returned vector is run throught he naive model and prediciton is produced. 
  
 