const { CognitoIdentityProviderClient, InitiateAuthCommand } = require('@aws-sdk/client-cognito-identity-provider')
const { createHmac } = require('crypto')

const COGNITO_CONFIG = {
  region: process.env.COGNITO_REGION || 'us-east-1',
  clientId: process.env.COGNITO_CLIENT_ID,
  clientSecret: process.env.COGNITO_CLIENT_SECRET,
  awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,
  awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
}

const cognitoClient = new CognitoIdentityProviderClient({
  region: COGNITO_CONFIG.region,
  credentials: {
    accessKeyId: COGNITO_CONFIG.awsAccessKeyId,
    secretAccessKey: COGNITO_CONFIG.awsSecretAccessKey
  }
})

const PERMISSION_MAP = {
  read: 'read',
  write: 'insert'
}

function getTokenData(token) {
  const tokenData = token.split('.')[1]
  return JSON.parse(Buffer.from(tokenData, 'base64').toString())
}

async function validate(request, response, next, hdbCore, logger) {
  const userData = {
    username: request.body.username,
    password: request.body.password
  }

  try {
    const authCommand = new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: COGNITO_CONFIG.clientId,
      AuthParameters: {
        USERNAME: userData.username,
        PASSWORD: userData.password,
        SECRET_HASH: createHmac('sha256', COGNITO_CONFIG.clientSecret)
          .update(userData.username + COGNITO_CONFIG.clientId)
          .digest('base64')
      }
    })

    const result = await cognitoClient.send(authCommand)
    if (!result.AuthenticationResult?.IdToken) {
      throw new Error('Invalid credentials')
    }

    const tokenData = getTokenData(result.AuthenticationResult.IdToken)
    if (!tokenData['custom:roles']) {
      throw new Error('User has no roles')
    }

    /* POPULATE USER ROLES IN REQUEST BODY */
    request.body.hdb_user = { role: { permission: {} } }
    tokenData['custom:roles'].split(',').forEach((role) => {
      const [schema, table, operation] = role.split('.')
      if (!request.body.hdb_user.role.permission[schema]) {
        request.body.hdb_user.role.permission[schema] = { tables: {} }
      }
      if (!request.body.hdb_user.role.permission[schema].tables[table]) {
        request.body.hdb_user.role.permission[schema].tables[table] = {
          read: false,
          insert: false,
          update: false,
          delete: false,
          attribute_permissions: []
        }
      }
      const permission = PERMISSION_MAP[operation]
      request.body.hdb_user.role.permission[schema].tables[table][permission] = true
    })
  } catch (error) {
    console.log('error', error)
    return response.code(500).send('Cognito Error')
  }
}

module.exports = { validate }
