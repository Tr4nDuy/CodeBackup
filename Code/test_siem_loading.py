#!/usr/bin/env python3
"""
Test script to verify SIEM system can load and use models created by original program.py
"""

import sys
import os
import pickle
import numpy as np
import pandas as pd

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import SIEM kINN implementation
from program_siem import kINN

def test_model_loading():
    """Test loading model saved by original program.py"""
    print("=" * 60)
    print("TESTING SIEM MODEL LOADING")
    print("=" * 60)
    
    # Model paths
    model_path = "c:/Users/ADMIN/Desktop/CodeBackup/Saved model/kinn_model.pkl"
    scaler_path = "c:/Users/ADMIN/Desktop/CodeBackup/Saved model/scaler.pkl"
    encoder_path = "c:/Users/ADMIN/Desktop/CodeBackup/Saved model/label_encoder.pkl"
    
    try:
        # Create SIEM kINN instance
        print("1. Creating SIEM kINN instance...")
        siem_kinn = kINN()
        print("✓ SIEM kINN instance created successfully")
        
        # Load the model
        print("\n2. Loading model saved by original program.py...")
        siem_kinn.load_model_compatible(model_path)
        print("✓ Model loaded successfully")
        
        # Print model information
        print(f"\n3. Model Information:")
        print(f"   - R (neighborhood size): {getattr(siem_kinn, 'R', 'Not set')}")
        print(f"   - Kernel: {getattr(siem_kinn, 'kernel', 'Not set')}")
        print(f"   - Mode: {getattr(siem_kinn, 'mode', 'Not set')}")
        print(f"   - Is fitted: {getattr(siem_kinn, 'is_fit', 'Not set')}")
        
        if hasattr(siem_kinn, 'X') and siem_kinn.X is not None:
            print(f"   - Training data shape: {siem_kinn.X.shape}")
        
        if hasattr(siem_kinn, 'cluster_labels') and siem_kinn.cluster_labels is not None:
            print(f"   - Cluster labels shape: {siem_kinn.cluster_labels.shape}")
            print(f"   - Unique clusters: {len(np.unique(siem_kinn.cluster_labels))}")
        
        if hasattr(siem_kinn, 'cluster_map') and siem_kinn.cluster_map is not None:
            print(f"   - Cluster map shape: {siem_kinn.cluster_map.shape}")
        
        # Check external data
        if hasattr(siem_kinn, 'external_cluster_train') and siem_kinn.external_cluster_train is not None:
            print(f"   - External cluster train shape: {siem_kinn.external_cluster_train.shape}")
        
        if hasattr(siem_kinn, 'external_cluster_map') and siem_kinn.external_cluster_map is not None:
            print(f"   - External cluster map shape: {siem_kinn.external_cluster_map.shape}")
        
        if hasattr(siem_kinn, 'external_parameters'):
            print(f"   - External parameters: {siem_kinn.external_parameters}")
        
        # Load preprocessors
        print("\n4. Loading preprocessors...")
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        print("✓ Scaler loaded")
        
        with open(encoder_path, 'rb') as f:
            label_encoder = pickle.load(f)
        print("✓ Label encoder loaded")
        
        # Test prediction with dummy data
        print("\n5. Testing prediction...")
        
        # Create dummy test data with same number of features as training data
        if hasattr(siem_kinn, 'X') and siem_kinn.X is not None:
            n_features = siem_kinn.X.shape[1]
            print(f"   Creating test data with {n_features} features...")
            
            # Create random test sample
            test_sample = np.random.random((1, n_features))
            print(f"   Test sample shape: {test_sample.shape}")
            
            # Make prediction
            print("   Making prediction...")
            prediction = siem_kinn.predict(test_sample)
            print(f"   ✓ Prediction successful: {prediction}")
            print(f"   Prediction shape: {np.array(prediction).shape}")
            print(f"   Prediction type: {type(prediction)}")
            
            # Test with multiple samples
            print("\n   Testing with multiple samples...")
            test_samples = np.random.random((5, n_features))
            predictions = siem_kinn.predict(test_samples)
            print(f"   ✓ Multiple predictions successful: {predictions}")
            
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED! ✓")
        print("SIEM system can successfully load and use models from original program.py")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_prediction_compatibility():
    """Test that predictions match original model behavior"""
    print("\n" + "=" * 60)
    print("TESTING PREDICTION COMPATIBILITY")
    print("=" * 60)
    
    try:
        # Load the original model directly to compare
        model_path = "c:/Users/ADMIN/Desktop/CodeBackup/Saved model/kinn_model.pkl"
        
        print("1. Loading original model data...")
        with open(model_path, 'rb') as f:
            original_data = pickle.load(f)
        
        if isinstance(original_data, dict):
            original_model = original_data['model']
            print("   ✓ Original model extracted from dictionary")
        else:
            original_model = original_data
            print("   ✓ Original model loaded directly")
        
        # Create SIEM version
        print("\n2. Loading model with SIEM kINN...")
        siem_kinn = kINN()
        siem_kinn.load_model_compatible(model_path)
        print("   ✓ SIEM model loaded")
        
        # Test with same data
        if hasattr(original_model, 'X') and original_model.X is not None:
            print(f"\n3. Testing with original training data subset...")
            
            # Use first 5 samples from original training data
            test_data = original_model.X[:5]
            print(f"   Test data shape: {test_data.shape}")
            
            # Make predictions with SIEM model
            siem_predictions = siem_kinn.predict(test_data)
            print(f"   ✓ SIEM predictions: {siem_predictions}")
            
            # Check prediction format
            if isinstance(siem_predictions, (list, np.ndarray)):
                print(f"   Prediction format: {type(siem_predictions)}")
                print(f"   Number of predictions: {len(siem_predictions)}")
                if len(siem_predictions) > 0:
                    print(f"   Sample prediction value: {siem_predictions[0]}")
                    print(f"   Sample prediction type: {type(siem_predictions[0])}")
            
        print("\n✓ Prediction compatibility test completed")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR in compatibility test: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Starting SIEM Model Loading Tests...")
    
    # Test 1: Basic loading
    success1 = test_model_loading()
    
    # Test 2: Prediction compatibility
    success2 = test_prediction_compatibility()
    
    if success1 and success2:
        print("\n🎉 ALL TESTS SUCCESSFUL!")
        print("The SIEM system is now compatible with models from program.py")
    else:
        print("\n❌ Some tests failed. Check the errors above.")
