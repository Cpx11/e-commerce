# e-commerce

rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function isSignedIn() { return request.auth != null; }
    function isAdmin() {
      return isSignedIn() &&
        get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }

    // Users: a user reads/updates their own doc; admins read/write all
    match /users/{uid} {
      allow read: if isSignedIn() && (request.auth.uid == uid || isAdmin());
      allow create: if isSignedIn() && request.auth.uid == uid;
      allow update, delete: if isAdmin() || request.auth.uid == uid;
    }

    // Products: public read, admin write
    match /products/{id} {
      allow read: if true;
      allow write: if isAdmin();
    }

    // Orders: owner reads own, admin reads/writes all
    match /orders/{id} {
      allow read: if isSignedIn() && (resource.data.userId == request.auth.uid || isAdmin());
      allow create: if isSignedIn();
      allow update, delete: if isAdmin();
    }

    // Settings (store config)
    match /settings/{id} {
      allow read: if true;
      allow write: if isAdmin();
    }

    // Notifications
    match /notifications/{id} {
      allow read: if isSignedIn();
      allow write: if isAdmin();
    }
  }
}