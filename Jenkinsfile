// def sonarBadge = addEmbeddableBadgeConfiguration(id:"sonarstatus", subject:"SonarQube QG")
pipeline {
    /* Declarative Pipeline here */

    /* Defining the environment */
    environment {
        scannerHome = tool 'SonarQube Scanner'
    }

    // agent any
    agent any

    stages {
        /* The stages here define a sequential pipeline (declarative pipeline) in Jenkins */
        /* Utilities - Utilities */
        stage ("Code Review"){
            /* This stage will perform code review of the code and sleep for 5 seconds to complete the code analysis and publish the results */
            steps{
                echo "Starting code review"
                script {
                    // sonarBadge.setStatus('running')
                    withCredentials([string(credentialsId: 'sonar-utilities-key', variable: 'sonarUtilSecret')]){
                        withSonarQubeEnv() {
                            sh "$scannerHome/bin/sonar-scanner \
                            -Dsonar.projectKey=Utilities \
                            -Dsonar.host.url=http://192.168.4.2:9000 \
                            -Dsonar.login=${sonarUtilSecret} \
                            -Dsonar.sources=/var/jenkins_home/workspace/Utilities \
                            -Dsonar.scm.provider=git"
                        }
                        sleep(30)
                        timeout(time: 1, unit:'MINUTES') {
                            def qg = waitForQualityGate()
                            echo qg.status
                        }
                    }
                }
                echo "Code Review Completed"
            }
        }

        // stage ("Quality Gate"){
        //     /* This stage will await the results of the Quality Gate from SonarQube in order to make a decision to proceed or abort the pipeline */
        //     steps{
        //         echo "Checking Quality Gate status"
        //         timeout(time: 1, unit:'MINUTES') {
        //             waitForQualityGate abortPipeline: true
        //         }
        //         echo "Quality Gate Status : OK"
        //     }
        // }
        
        // stage ("Build") {
        //     /* This stage shall build a docker image with the Dockerfile present in the repository with the latest tag */
        //     steps {
        //         echo "Starting Build"
        //         script {
        //             dockerImage = docker.build registry + ":latest"
        //         }
        //         echo "Build Completed"
        //     }
        // }

        // stage ("Publish") {
        //     /* This stage shall publish the docker image to the hub.docker.com */
        //     steps {
        //         echo "Publishing built image ($registry:latest) to the docker registry"
        //         script {
        //             docker.withRegistry('', registryCredentials) {
        //                 dockerImage.push()
        //             }
        //             // sh "docker rmi $registry:latest"
        //         }
        //         echo "Published image successfully"
        //     }
        // }

        // stage ('VA and Compliance') {
        //     steps {
        //         echo "Starting VA and Compliance for the $registry:latest image"
        //         sh 'echo "invad3rsam/flaskapp:latest `pwd`/Dockerfile" > anchore_images'
        //         // anchore name: 'anchore_images', policyBundleId: 'anchore_cis_1.13.0_base', bailOnFail: false, bailOnPluginFail: false
        //         anchore name: 'anchore_images', bailOnFail: true, bailOnPluginFail: false
        //         echo "VA and Compliance for $registry:latest image completed"
        //     }
        // }

        // stage ("Deployment") {
        //     /* Deploy Container on UAT and Staging */
        //     parallel {
        //         stage ("UAT") {
        //             steps {
        //                 script {
        //                     echo "Deployment started on UAT container - using image $registry:latest"
        //                     try {
        //                         sh "docker stop flaskapp-uat"
        //                     } catch (err) {
        //                         echo "Error in stopping the container."
        //                         echo err.getMessage()
        //                     }
        //                     try {
        //                         sh "docker rm flaskapp-uat"
        //                     } catch (err) {
        //                         echo "Error in removing the container."
        //                         echo err.getMessage()
        //                     }
        //                     sh "docker run -d --name flaskapp-uat --env app_env=UAT --restart=always -p 5000:5000 $registry:latest"
        //                     echo "Deployment completed - UAT"
        //                 }
        //             }
        //         }
        //         stage ("DEV") {
        //             steps {
        //                 script {
        //                     echo "Deployment started on DEV container - using image $registry:latest"
        //                     try {
        //                         sh "docker stop flaskapp-dev"
        //                     } 
        //                     catch (err) {
        //                         echo "Error in stopping the container."
        //                         echo err.getMessage()
        //                     }
        //                     try {
        //                         sh "docker rm flaskapp-dev"
        //                     } 
        //                     catch (err) {
        //                         echo "Error in removing the container."
        //                         echo err.getMessage()
        //                     }
        //                     sh "docker run -d --name flaskapp-dev --env app_env=DEV --restart=always -p 5001:5000 $registry:latest"
        //                     echo "Deployment completed - DEV"
        //                 }
        //             }
        //         }
        //         stage ("SIT") {
        //             steps {
        //                 script {
        //                     echo "Deployment started on SIT container - using image $registry:latest"
        //                     try {
        //                         sh "docker stop flaskapp-sit"
        //                     } 
        //                     catch (err) {
        //                         echo "Error in stopping the container."
        //                         echo err.getMessage()
        //                     }
        //                     try {
        //                         sh "docker rm flaskapp-sit"
        //                     } 
        //                     catch (err) {
        //                         echo "Error in removing the container."
        //                         echo err.getMessage()
        //                     }
        //                     sh "docker run -d --name flaskapp-sit --env app_env=SIT --restart=always -p 5002:5000 $registry:latest"
        //                     echo "Deployment completed - SIT"
        //                 }
        //             }
        //         }
                
        //     }
        // }
        // stage ("Staging") {
        //     steps {
        //         script {
        //             echo "Deployment started on STAG container - using image $registry:latest"
        //             try {
        //                 sh "docker stop flaskapp-prod"
        //             } 
        //             catch (err) {
        //                 echo "Error in stopping the container."
        //                 echo err.getMessage()
        //             }
        //             try {
        //                 sh "docker rm flaskapp-prod"
        //             } 
        //             catch (err) {
        //                 echo "Error in removing the container."
        //                 echo err.getMessage()
        //             }
        //             sh "docker run -d --name flaskapp-stag --env app_env=STAG --restart=always -p 2080:5000 $registry:latest"
        //             echo "Deployment completed - STAG"
        //         }
        //     }
        // }
        // stage ("Production") {
        //     /* This stage will await the confirmation from the user to deploy on Production and then deploy a production container */
        //     input {
        //         message "Confirm to move on Production"
        //     }
        //     steps {
        //         script {
        //             echo "Deployment started on PROD container - using image $registry:latest"
        //             try {
        //                 // sh "docker stop flaskapp-prod"
        //                 sh "docker stop flaskapp-stag"
        //             } 
        //             catch (err) {
        //                 echo "Error in stopping the container."
        //                 echo err.getMessage()
        //             }
        //             try {
        //                 sh "docker rm flaskapp-stag"
        //             } 
        //             catch (err) {
        //                 echo "Error in removing the container."
        //                 echo err.getMessage()
        //             }
        //             sh "docker run -d --name flaskapp-prod --env app_env=PROD --restart=always -p 2080:5000 $registry:latest"
        //             echo "Deployment completed - PROD"
        //         }
        //     }
        // }

        // stage ("Clean Up") {
        //     /* This stage shall clean up the remnants from the image creation stage (Build Stage) */
        //     steps {
        //         echo "Cleaning up"
        //         sh "docker rmi -f \$(docker images -q --filter \"dangling=true\")"
        //         echo "Clean Up Completed"
        //     }
        // }
    }

    post {
        /* Once the pipeline is finished / aborted / timedout, this code shall run and display a message 'Pipeline Completed' */
        always {
            echo 'Pipeline Completed.'
            // emailext body: "${currentBuild.currentResult}: Job ${env.JOB_NAME} build ${env.BUILD_NUMBER}\n More info at: ${env.BUILD_URL}",
            //     recipientProviders: [[$class: 'DevelopersRecipientProvider'], [$class: 'RequesterRecipientProvider']],
            //     subject: "Jenkins Build ${currentBuild.currentResult}: Job ${env.JOB_NAME}"
        }
    }
}
