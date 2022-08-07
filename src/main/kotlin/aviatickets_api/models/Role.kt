package aviatickets_api.models

import javax.persistence.*


@Entity
@Table(name = "roles")
class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Int = 0

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    var name: ERole = ERole.ROLE_USER

    constructor()
    constructor(name: ERole) {
        this.name = name
    }
}