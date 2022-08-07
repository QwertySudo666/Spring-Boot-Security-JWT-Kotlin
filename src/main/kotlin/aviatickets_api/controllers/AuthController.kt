package aviatickets_api.controllers

import aviatickets_api.models.ERole
import aviatickets_api.models.Role
import aviatickets_api.models.User
import aviatickets_api.repository.RoleRepository
import aviatickets_api.repository.UserRepository
import aviatickets_api.security.jwt.JwtUtils
import aviatickets_api.security.services.UserDetailsImpl
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import aviatickets_api.payload.request.LoginRequest
import aviatickets_api.payload.request.SignupRequest
import aviatickets_api.payload.response.MessageResponse
import aviatickets_api.payload.response.UserInfoResponse
import java.util.function.Consumer
import java.util.stream.Collectors
import javax.validation.Valid

@CrossOrigin(origins = ["*"], maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
class AuthController {
    @Autowired
    var authenticationManager: AuthenticationManager? = null

    @Autowired
    var userRepository: UserRepository? = null

    @Autowired
    var roleRepository: RoleRepository? = null

    @Autowired
    var encoder: PasswordEncoder? = null

    @Autowired
    var jwtUtils: JwtUtils? = null
    @PostMapping("/signin")
    fun authenticateUser(@RequestBody loginRequest: @Valid LoginRequest?): ResponseEntity<*> {
        val authentication = authenticationManager
            ?.authenticate(UsernamePasswordAuthenticationToken(loginRequest!!.username, loginRequest.password))
        SecurityContextHolder.getContext().authentication = authentication
        val userDetails = authentication!!.principal as UserDetailsImpl
        val jwtCookie = jwtUtils!!.generateJwtCookie(userDetails)
        val roles = userDetails.authorities.stream()
            .map { item: GrantedAuthority -> item.authority }
            .collect(Collectors.toList())
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
            .body(
                UserInfoResponse(
                    userDetails.id,
                    userDetails.username,
                    userDetails.email,
                    roles
                )
            )
    }

    @PostMapping("/signup")
    fun registerUser(@RequestBody signUpRequest: @Valid SignupRequest?): ResponseEntity<*> {
        if (userRepository!!.existsByUsername(signUpRequest!!.username)!!) {
            return ResponseEntity.badRequest().body(MessageResponse("Error: Username is already taken!"))
        }
        if (userRepository!!.existsByEmail(signUpRequest.email)!!) {
            return ResponseEntity.badRequest().body(MessageResponse("Error: Email is already in use!"))
        }
        // Create new user's account
        val user = User(
            signUpRequest.username!!,
            signUpRequest.email!!,
            encoder!!.encode(signUpRequest.password)
        )
        val strRoles = signUpRequest.role
        val roles: MutableSet<Role> = HashSet()
        if (strRoles == null) {
            val userRole: Role = roleRepository!!.findByName(ERole.ROLE_USER)
                ?.orElseThrow { RuntimeException("Error: Role is not found.") }!!
            roles.add(userRole)
        } else {
            strRoles.forEach(Consumer { role: String? ->
                when (role) {
                    "admin" -> {
                        val adminRole: Role = roleRepository!!.findByName(ERole.ROLE_ADMIN)
                            ?.orElseThrow {
                                RuntimeException(
                                    "Error: Role is not found."
                                )
                            }!!
                        roles.add(adminRole)
                    }
                    "mod" -> {
                        val modRole: Role = roleRepository!!.findByName(ERole.ROLE_MODERATOR)
                            ?.orElseThrow {
                                RuntimeException(
                                    "Error: Role is not found."
                                )
                            }!!
                        roles.add(modRole)
                    }
                    else -> {
                        val userRole: Role = roleRepository!!.findByName(ERole.ROLE_USER)
                            ?.orElseThrow {
                                RuntimeException(
                                    "Error: Role is not found."
                                )
                            }!!
                        roles.add(userRole)
                    }
                }
            })
        }
        user.roles=roles
        userRepository!!.save(user)
        return ResponseEntity.ok(MessageResponse("User registered successfully!"))
    }

    @PostMapping("/signout")
    fun logoutUser(): ResponseEntity<*> {
        val cookie = jwtUtils!!.cleanJwtCookie
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
            .body(MessageResponse("You've been signed out!"))
    }
}