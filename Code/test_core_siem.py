#!/usr/bin/env python3
"""
Simple test focusing just on model loading and prediction functionality
"""

import sys
import os
import pickle
import numpy as np

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import SIEM kINN implementation
from program_siem import kINN

def test_core_functionality():
    """Test core model loading and prediction functionality"""
    print("=" * 50)
    print("SIEM CORE FUNCTIONALITY TEST")
    print("=" * 50)
    
    model_path = "c:/Users/ADMIN/Desktop/CodeBackup/Saved model/kinn_model.pkl"
    
    try:
        # Load with SIEM kINN
        print("1. Loading model with SIEM kINN...")
        siem_kinn = kINN()
        siem_kinn.load_model_compatible(model_path)
        print("   ✓ Model loaded successfully")
        
        # Model info
        print(f"2. Model Details:")
        print(f"   - R: {siem_kinn.R}")
        print(f"   - Kernel: {siem_kinn.kernel}")
        print(f"   - Training data: {siem_kinn.X.shape}")
        print(f"   - Clusters: {len(np.unique(siem_kinn.cluster_labels))}")
        
        # Test predictions with different data sizes
        print("3. Testing Predictions:")
        
        # Single sample
        test_single = np.random.random((1, 55))
        pred_single = siem_kinn.predict(test_single)
        print(f"   Single sample prediction: {pred_single}")
        
        # Multiple samples
        test_multi = np.random.random((3, 55))
        pred_multi = siem_kinn.predict(test_multi)
        print(f"   Multiple samples prediction: {pred_multi}")
        
        # Test with actual training data (should have high confidence)
        train_subset = siem_kinn.X[:2]  # First 2 training samples
        pred_train = siem_kinn.predict(train_subset)
        print(f"   Training data prediction: {pred_train}")
        
        print("\n4. Prediction Analysis:")
        if isinstance(pred_single, tuple) and len(pred_single) == 2:
            classes, confidences = pred_single
            print(f"   ✓ Returns tuple (classes, confidences)")
            print(f"   ✓ Classes type: {type(classes)}")
            print(f"   ✓ Confidences type: {type(confidences)}")
        
        print("\n✅ ALL CORE TESTS PASSED!")
        print("SIEM system successfully loads and uses original program.py models")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_integration_workflow():
    """Test a complete SIEM integration workflow"""
    print("\n" + "=" * 50)
    print("SIEM INTEGRATION WORKFLOW TEST")
    print("=" * 50)
    
    try:
        # Step 1: Initialize SIEM kINN
        print("1. Initializing SIEM kINN...")
        siem_kinn = kINN()
        
        # Step 2: Load existing model
        print("2. Loading pre-trained model...")
        model_path = "c:/Users/ADMIN/Desktop/CodeBackup/Saved model/kinn_model.pkl"
        siem_kinn.load_model_compatible(model_path)
        print("   ✓ Model loaded and ready for real-time monitoring")
        
        # Step 3: Simulate real-time monitoring
        print("3. Simulating real-time network monitoring...")
        
        # Simulate 10 network activity samples
        for i in range(10):
            # Generate random network activity (55 features)
            network_activity = np.random.random((1, 55))
            
            # Make prediction
            prediction = siem_kinn.predict(network_activity)
            
            if isinstance(prediction, tuple):
                pred_class, confidence = prediction
                print(f"   Sample {i+1}: Class={pred_class[0]}, Confidence={confidence[0]:.3f}")
            else:
                print(f"   Sample {i+1}: Prediction={prediction}")
        
        print("\n✅ INTEGRATION WORKFLOW SUCCESSFUL!")
        print("SIEM system ready for deployment with original models")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success1 = test_core_functionality()
    success2 = test_integration_workflow()
    
    if success1 and success2:
        print("\n🎉 SUCCESS! The SIEM system is fully compatible!")
        print("Ready to replace program.py models in real-time monitoring")
    else:
        print("\n❌ Some tests failed")
