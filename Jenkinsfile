Jenkinsfile (Declarative Pipeline)
pipeline {
    agent { docker { image 'python:3.5.2' } }
    stages {
        stage('build') {
            steps {
                sh 'python --version'
            }
        }
    }
}
