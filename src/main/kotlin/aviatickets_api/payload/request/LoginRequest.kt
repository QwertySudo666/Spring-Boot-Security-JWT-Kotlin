package aviatickets_api.payload.request

import javax.validation.constraints.NotBlank


class LoginRequest {
    var username: @NotBlank String? = null
    var password: @NotBlank String? = null
}