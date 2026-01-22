"""
Anomaly Detection Analysis for Cybersecurity Attacks Dataset
Analyzes network traffic data to identify anomalous patterns
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings('ignore')

# Set visualization style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)

def load_and_explore_data(filepath):
    """Load and perform initial exploration of the dataset"""
    print("=" * 80)
    print("LOADING AND EXPLORING DATA")
    print("=" * 80)
    
    df = pd.read_csv(filepath)
    
    print(f"\nDataset Shape: {df.shape}")
    print(f"Total Records: {df.shape[0]:,}")
    print(f"Total Features: {df.shape[1]}")
    
    print("\n--- Column Names ---")
    print(df.columns.tolist())
    
    print("\n--- Data Types ---")
    print(df.dtypes)
    
    print("\n--- Missing Values ---")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df)) * 100
    missing_df = pd.DataFrame({
        'Missing Count': missing,
        'Percentage': missing_pct
    })
    print(missing_df[missing_df['Missing Count'] > 0])
    
    print("\n--- Basic Statistics ---")
    print(df.describe())
    
    return df

def analyze_attack_distribution(df):
    """Analyze the distribution of attack types"""
    print("\n" + "=" * 80)
    print("ATTACK TYPE DISTRIBUTION")
    print("=" * 80)
    
    if 'Attack Type' in df.columns:
        attack_dist = df['Attack Type'].value_counts()
        print("\n--- Attack Type Counts ---")
        print(attack_dist)
        
        print("\n--- Attack Type Percentages ---")
        print(df['Attack Type'].value_counts(normalize=True) * 100)
        
        # Visualize
        plt.figure(figsize=(10, 6))
        attack_dist.plot(kind='bar', color='coral')
        plt.title('Distribution of Attack Types')
        plt.xlabel('Attack Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('data/cybersecurity_attacks/attack_distribution.png')
        print("\nSaved: attack_distribution.png")
        plt.close()

def analyze_anomaly_scores(df):
    """Analyze existing anomaly scores in the dataset"""
    print("\n" + "=" * 80)
    print("ANOMALY SCORE ANALYSIS")
    print("=" * 80)
    
    if 'Anomaly Scores' in df.columns:
        df['Anomaly Scores'] = pd.to_numeric(df['Anomaly Scores'], errors='coerce')
        
        print(f"\n--- Anomaly Score Statistics ---")
        print(df['Anomaly Scores'].describe())
        
        # Find high anomaly scores
        high_anomaly_threshold = df['Anomaly Scores'].quantile(0.95)
        high_anomalies = df[df['Anomaly Scores'] > high_anomaly_threshold]
        
        print(f"\n--- High Anomaly Scores (>{high_anomaly_threshold:.2f}) ---")
        print(f"Count: {len(high_anomalies)}")
        print(f"Percentage: {(len(high_anomalies) / len(df)) * 100:.2f}%")
        
        if 'Attack Type' in df.columns:
            print("\n--- Attack Types in High Anomaly Records ---")
            print(high_anomalies['Attack Type'].value_counts())
        
        # Visualize
        plt.figure(figsize=(12, 6))
        plt.subplot(1, 2, 1)
        plt.hist(df['Anomaly Scores'].dropna(), bins=50, color='steelblue', edgecolor='black')
        plt.title('Anomaly Score Distribution')
        plt.xlabel('Anomaly Score')
        plt.ylabel('Frequency')
        plt.axvline(high_anomaly_threshold, color='red', linestyle='--', label=f'95th percentile ({high_anomaly_threshold:.2f})')
        plt.legend()
        
        plt.subplot(1, 2, 2)
        plt.boxplot(df['Anomaly Scores'].dropna())
        plt.title('Anomaly Score Box Plot')
        plt.ylabel('Anomaly Score')
        
        plt.tight_layout()
        plt.savefig('data/cybersecurity_attacks/anomaly_score_analysis.png')
        print("\nSaved: anomaly_score_analysis.png")
        plt.close()
        
        return high_anomalies

def prepare_features_for_ml(df):
    """Prepare features for machine learning anomaly detection"""
    print("\n" + "=" * 80)
    print("FEATURE ENGINEERING")
    print("=" * 80)
    
    # Select numeric and categorical features
    feature_df = df.copy()
    
    # Convert Anomaly Scores to numeric
    if 'Anomaly Scores' in feature_df.columns:
        feature_df['Anomaly Scores'] = pd.to_numeric(feature_df['Anomaly Scores'], errors='coerce')
    
    # Numeric features
    numeric_features = []
    
    if 'Source Port' in feature_df.columns:
        numeric_features.append('Source Port')
    if 'Destination Port' in feature_df.columns:
        numeric_features.append('Destination Port')
    if 'Packet Length' in feature_df.columns:
        numeric_features.append('Packet Length')
    if 'Anomaly Scores' in feature_df.columns:
        numeric_features.append('Anomaly Scores')
    
    # Categorical features to encode
    categorical_features = []
    
    if 'Protocol' in feature_df.columns:
        categorical_features.append('Protocol')
    if 'Packet Type' in feature_df.columns:
        categorical_features.append('Packet Type')
    if 'Traffic Type' in feature_df.columns:
        categorical_features.append('Traffic Type')
    if 'Severity Level' in feature_df.columns:
        categorical_features.append('Severity Level')
    if 'Malware Indicators' in feature_df.columns:
        categorical_features.append('Malware Indicators')
    
    print(f"\nNumeric Features: {numeric_features}")
    print(f"Categorical Features: {categorical_features}")
    
    # Create feature matrix
    X = pd.DataFrame()
    
    # Add numeric features
    for feat in numeric_features:
        X[feat] = pd.to_numeric(feature_df[feat], errors='coerce')
    
    # Encode categorical features
    le = LabelEncoder()
    for feat in categorical_features:
        try:
            X[feat + '_encoded'] = le.fit_transform(feature_df[feat].fillna('Unknown'))
        except:
            print(f"Warning: Could not encode {feat}")
    
    # Fill missing values
    X = X.fillna(X.median())
    
    print(f"\nFeature Matrix Shape: {X.shape}")
    print(f"Features: {X.columns.tolist()}")
    
    return X, feature_df

def detect_anomalies_isolation_forest(X, df):
    """Use Isolation Forest to detect anomalies"""
    print("\n" + "=" * 80)
    print("ISOLATION FOREST ANOMALY DETECTION")
    print("=" * 80)
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    print("\nTraining Isolation Forest model...")
    iso_forest = IsolationForest(
        contamination=0.1,  # Expect 10% anomalies
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        verbose=0
    )
    
    # Predict anomalies (-1 for anomalies, 1 for normal)
    predictions = iso_forest.fit_predict(X_scaled)
    anomaly_scores = iso_forest.score_samples(X_scaled)
    
    # Add predictions to dataframe
    df['IF_Anomaly'] = predictions
    df['IF_Anomaly_Score'] = -anomaly_scores  # Invert so higher = more anomalous
    
    # Count anomalies
    anomaly_count = (predictions == -1).sum()
    normal_count = (predictions == 1).sum()
    
    print(f"\nResults:")
    print(f"Total Records: {len(df):,}")
    print(f"Anomalies Detected: {anomaly_count:,} ({(anomaly_count/len(df))*100:.2f}%)")
    print(f"Normal Records: {normal_count:,} ({(normal_count/len(df))*100:.2f}%)")
    
    # Analyze anomalies
    anomalies = df[df['IF_Anomaly'] == -1]
    
    print("\n--- Top 10 Most Anomalous Records ---")
    top_anomalies = df.nlargest(10, 'IF_Anomaly_Score')
    display_cols = ['Source IP Address', 'Destination IP Address', 'Attack Type', 
                    'Severity Level', 'IF_Anomaly_Score']
    display_cols = [col for col in display_cols if col in top_anomalies.columns]
    print(top_anomalies[display_cols].to_string(index=False))
    
    if 'Attack Type' in anomalies.columns:
        print("\n--- Attack Types in Detected Anomalies ---")
        print(anomalies['Attack Type'].value_counts())
    
    if 'Severity Level' in anomalies.columns:
        print("\n--- Severity Levels in Detected Anomalies ---")
        print(anomalies['Severity Level'].value_counts())
    
    return df, anomalies

def detect_anomalies_dbscan(X, df):
    """Use DBSCAN clustering to detect anomalies"""
    print("\n" + "=" * 80)
    print("DBSCAN CLUSTERING ANOMALY DETECTION")
    print("=" * 80)
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Reduce dimensions for better clustering
    print("\nReducing dimensions with PCA...")
    pca = PCA(n_components=min(5, X_scaled.shape[1]))
    X_pca = pca.fit_transform(X_scaled)
    
    print(f"Explained Variance Ratio: {pca.explained_variance_ratio_}")
    print(f"Total Variance Explained: {pca.explained_variance_ratio_.sum():.2%}")
    
    # Apply DBSCAN
    print("\nApplying DBSCAN clustering...")
    dbscan = DBSCAN(eps=0.5, min_samples=50)
    clusters = dbscan.fit_predict(X_pca)
    
    # -1 indicates outliers/anomalies
    df['DBSCAN_Cluster'] = clusters
    
    anomaly_count = (clusters == -1).sum()
    n_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
    
    print(f"\nResults:")
    print(f"Number of Clusters: {n_clusters}")
    print(f"Outliers (Anomalies): {anomaly_count:,} ({(anomaly_count/len(df))*100:.2f}%)")
    
    print("\n--- Cluster Distribution ---")
    cluster_counts = pd.Series(clusters).value_counts().sort_index()
    print(cluster_counts)
    
    # Analyze outliers
    if anomaly_count > 0:
        outliers = df[df['DBSCAN_Cluster'] == -1]
        
        if 'Attack Type' in outliers.columns:
            print("\n--- Attack Types in DBSCAN Outliers ---")
            print(outliers['Attack Type'].value_counts())
        
        if 'Severity Level' in outliers.columns:
            print("\n--- Severity Levels in DBSCAN Outliers ---")
            print(outliers['Severity Level'].value_counts())
    
    return df

def visualize_anomalies(df, X):
    """Visualize detected anomalies using PCA"""
    print("\n" + "=" * 80)
    print("VISUALIZING ANOMALIES")
    print("=" * 80)
    
    # Standardize and apply PCA
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    
    # Create visualization
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    
    # Plot 1: Isolation Forest results
    if 'IF_Anomaly' in df.columns:
        colors = ['red' if x == -1 else 'blue' for x in df['IF_Anomaly']]
        axes[0].scatter(X_pca[:, 0], X_pca[:, 1], c=colors, alpha=0.5, s=10)
        axes[0].set_title('Isolation Forest Anomaly Detection')
        axes[0].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        axes[0].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor='blue', label='Normal'),
                          Patch(facecolor='red', label='Anomaly')]
        axes[0].legend(handles=legend_elements)
    
    # Plot 2: DBSCAN results
    if 'DBSCAN_Cluster' in df.columns:
        colors = ['red' if x == -1 else 'blue' for x in df['DBSCAN_Cluster']]
        axes[1].scatter(X_pca[:, 0], X_pca[:, 1], c=colors, alpha=0.5, s=10)
        axes[1].set_title('DBSCAN Clustering Anomaly Detection')
        axes[1].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        axes[1].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        
        legend_elements = [Patch(facecolor='blue', label='Clustered'),
                          Patch(facecolor='red', label='Outlier')]
        axes[1].legend(handles=legend_elements)
    
    plt.tight_layout()
    plt.savefig('data/cybersecurity_attacks/anomaly_detection_visualization.png')
    print("\nSaved: anomaly_detection_visualization.png")
    plt.close()

def save_anomaly_report(df):
    """Save detailed anomaly report to CSV"""
    print("\n" + "=" * 80)
    print("SAVING ANOMALY REPORT")
    print("=" * 80)
    
    # Save all anomalies detected by Isolation Forest
    if 'IF_Anomaly' in df.columns:
        anomalies = df[df['IF_Anomaly'] == -1].copy()
        anomalies = anomalies.sort_values('IF_Anomaly_Score', ascending=False)
        
        output_file = 'data/cybersecurity_attacks/detected_anomalies.csv'
        anomalies.to_csv(output_file, index=False)
        print(f"\nSaved {len(anomalies):,} anomalies to: {output_file}")
        
        # Save top 100 most anomalous records
        top_100 = df.nlargest(100, 'IF_Anomaly_Score')
        top_100_file = 'data/cybersecurity_attacks/top_100_anomalies.csv'
        top_100.to_csv(top_100_file, index=False)
        print(f"Saved top 100 anomalies to: {top_100_file}")

def main():
    """Main analysis pipeline"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "ANOMALY DETECTION ANALYSIS" + " " * 32 + "║")
    print("║" + " " * 18 + "Cybersecurity Attacks Dataset" + " " * 31 + "║")
    print("╚" + "=" * 78 + "╝")
    
    # File path
    filepath = 'data/cybersecurity_attacks/cybersecurity_attacks.csv'
    
    try:
        # Load and explore data
        df = load_and_explore_data(filepath)
        
        # Analyze attack distribution
        analyze_attack_distribution(df)
        
        # Analyze existing anomaly scores
        high_anomalies = analyze_anomaly_scores(df)
        
        # Prepare features for ML
        X, df = prepare_features_for_ml(df)
        
        # Detect anomalies using Isolation Forest
        df, if_anomalies = detect_anomalies_isolation_forest(X, df)
        
        # Detect anomalies using DBSCAN
        df = detect_anomalies_dbscan(X, df)
        
        # Visualize results
        visualize_anomalies(df, X)
        
        # Save report
        save_anomaly_report(df)
        
        print("\n" + "=" * 80)
        print("ANALYSIS COMPLETE!")
        print("=" * 80)
        print("\nGenerated Files:")
        print("  - attack_distribution.png")
        print("  - anomaly_score_analysis.png")
        print("  - anomaly_detection_visualization.png")
        print("  - detected_anomalies.csv")
        print("  - top_100_anomalies.csv")
        print("\n")
        
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
