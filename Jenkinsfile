buildBranch=env.BRANCH_NAME

node () {
    properties([[$class: 'jenkins.model.BuildDiscarderProperty',
                strategy: [$class: 'LogRotator',
                            numToKeepStr: '10',
                            artifactNumToKeepStr: '10']]])

    stage 'Checking out Project'
    checkout scm

    stage 'Building'
    mvn( '-U clean package -fn')

    if ( buildBranch.endsWith('-develop')) {
            stage 'Deploying Artifacts'
            mvn ('-U -DskipTests deploy')
    }

    stage 'Archiving Artifacts'
    archive includes:'**/target/*.jar'
    step $class: 'JUnitResultArchiver', testResults: '**/TEST-*.xml'

    // Trigger the Downstream jobs
    // tryToBuild('Secrata Packaging - Develop - Multibranch')
}


def mvn(args) {
    sh "${tool 'Maven 3.0'}/bin/mvn ${args}"
}

def tryToBuild(job) {
    try {
        jobName = job + "/" + buildBranch
        echo "Trying to build: '" + jobName + "'"
        build job: jobName, quietPeriod: 10, wait: false
    } catch (all) {
        echo "Unable to launch downstream job: " + jobName
    }
}

